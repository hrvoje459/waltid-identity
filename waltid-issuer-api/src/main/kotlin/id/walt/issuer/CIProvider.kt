@file:Suppress("ExtractKtorModule")

package id.walt.issuer


import COSE.AlgorithmID
import COSE.OneKey
import cbor.Cbor
import id.walt.credentials.issuance.Issuer.mdocIssue
import id.walt.credentials.issuance.Issuer.mergingJwtIssue
import id.walt.credentials.issuance.Issuer.mergingSdJwtIssue
import id.walt.credentials.vc.vcs.W3CVC
import id.walt.crypto.keys.Key
import id.walt.crypto.keys.KeySerialization
import id.walt.crypto.keys.KeyType
import id.walt.crypto.keys.jwk.JWKKey
import id.walt.did.dids.DidService
import id.walt.issuer.IssuanceExamples.openBadgeCredentialExample
import id.walt.issuer.base.config.ConfigManager
import id.walt.issuer.base.config.OIDCIssuerServiceConfig
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.CredentialSupported
import id.walt.oid4vc.definitions.JWTClaims
import id.walt.oid4vc.errors.CredentialError
import id.walt.oid4vc.errors.DeferredCredentialError
import id.walt.oid4vc.interfaces.CredentialResult
import id.walt.oid4vc.providers.CredentialIssuerConfig
import id.walt.oid4vc.providers.IssuanceSession
import id.walt.oid4vc.providers.OpenIDCredentialIssuer
import id.walt.oid4vc.providers.TokenTarget
import id.walt.oid4vc.requests.BatchCredentialRequest
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.responses.BatchCredentialResponse
import id.walt.oid4vc.responses.CredentialErrorCode
import id.walt.oid4vc.responses.CredentialResponse
import id.walt.oid4vc.util.randomUUID
import id.walt.sdjwt.SDMap
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration.Companion.minutes


import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jose.util.X509CertUtils
import id.walt.credentials.issuance.Issuer.mergingToVc
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.dataelement.*
import id.walt.mdoc.doc.MDocBuilder
import id.walt.mdoc.mso.DeviceKeyInfo
import id.walt.mdoc.mso.ValidityInfo
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.LocalDate
import kotlinx.datetime.plus
import kotlinx.serialization.encodeToHexString
import java.security.cert.X509Certificate
import java.util.*

/**
 * OIDC for Verifiable Credential Issuance service provider, implementing abstract service provider from OIDC4VC library.
 */
open class CIProvider : OpenIDCredentialIssuer(
    baseUrl = let {
        ConfigManager.getConfig<OIDCIssuerServiceConfig>().baseUrl
    }, config = CredentialIssuerConfig(credentialsSupported = listOf(
//        "VerifiableCredential" to listOf("VerifiableCredential"),
        "BankId" to listOf("VerifiableCredential", "BankId"),
        "KycChecksCredential" to listOf("VerifiableCredential", "VerifiableAttestation", "KycChecksCredential"),
        "KycDataCredential" to listOf("VerifiableCredential", "VerifiableAttestation", "KycDataCredential"),
        "PassportCh" to listOf("VerifiableCredential", "VerifiableAttestation", "VerifiableId", "PassportCh"),
        "PND91Credential" to listOf("VerifiableCredential", "PND91Credential"),
        "MortgageEligibility" to listOf(
            "VerifiableCredential",
            "VerifiableAttestation",
            "VerifiableId",
            "MortgageEligibility"
        ),
        "PortableDocumentA1" to listOf("VerifiableCredential", "VerifiableAttestation", "PortableDocumentA1"),
        "OpenBadgeCredential" to listOf("VerifiableCredential", "OpenBadgeCredential"),
        "VaccinationCertificate" to listOf(
            "VerifiableCredential",
            "VerifiableAttestation",
            "VaccinationCertificate"
        ),
        "WalletHolderCredential" to listOf("VerifiableCredential", "WalletHolderCredential"),
        "UniversityDegree" to listOf("VerifiableCredential", "UniversityDegree"),
        "VerifiableId" to listOf("VerifiableCredential", "VerifiableAttestation", "VerifiableId"),
    ).map {
        CredentialSupported(
            format = CredentialFormat.jwt_vc_json,
            id = it.first,
            cryptographicBindingMethodsSupported = setOf("did"),
            cryptographicSuitesSupported = setOf("EdDSA", "ES256", "ES256K", "RSA"),
            types = it.second
        )
    }.plus(
        CredentialSupported(
            format = CredentialFormat.mso_mdoc,
            id = "Iso18013DriversLicenseCredential",
            cryptographicBindingMethodsSupported = setOf("did"),
            cryptographicSuitesSupported = setOf("EdDSA", "ES256", "ES256K", "RSA"),
            types = listOf("VerifiableCredential","Iso18013DriversLicenseCredential")
        )
    )

    )
) {
    companion object {

        val exampleIssuerKey by lazy { runBlocking { JWKKey.generate(KeyType.Ed25519) } }
        val exampleIssuerDid by lazy { runBlocking { DidService.registerByKey("jwk", exampleIssuerKey).did } }


        private val CI_TOKEN_KEY by lazy { runBlocking { JWKKey.generate(KeyType.Ed25519) } }
    }

    // -------------------------------
    // Simple in-memory session management
    private val authSessions: MutableMap<String, IssuanceSession> = mutableMapOf()


    var deferIssuance = false
    val deferredCredentialRequests = mutableMapOf<String, CredentialRequest>()
    override fun getSession(id: String): IssuanceSession? {
        println("RETRIEVING CI AUTH SESSION: $id")
        return authSessions[id]
    }

    override fun putSession(id: String, session: IssuanceSession): IssuanceSession? {
        println("SETTING CI AUTH SESSION: $id = $session")
        return authSessions.put(id, session)
    }

    override fun removeSession(id: String): IssuanceSession? {
        println("REMOVING CI AUTH SESSION: $id")
        return authSessions.remove(id)
    }

    // ------------------------------------------
    // Simple cryptographics operation interface implementations
    override fun signToken(target: TokenTarget, payload: JsonObject, header: JsonObject?, keyId: String?) =
        runBlocking {
            println("Signing JWS:   $payload")
            println("JWS Signature: target: $target, keyId: $keyId, header: $header")
            CI_TOKEN_KEY.signJws(payload.toString().toByteArray()).also {
                println("Signed JWS: >> $it")
            }
        }

    @OptIn(ExperimentalEncodingApi::class)
    override fun verifyTokenSignature(target: TokenTarget, token: String) = runBlocking {
        println("Verifying JWS: $token")
        println("JWS Verification: target: $target")

        println("JWS Verification: token: " + token)

        val tokenHeader = Json.parseToJsonElement(Base64.decode(token.split(".")[0]).decodeToString()).jsonObject
        if (tokenHeader["kid"] != null) {
            val did = tokenHeader["kid"]!!.jsonPrimitive.content.split("#")[0]
            println("Resolving DID: $did")
            val key = DidService.resolveToKey(did).getOrThrow()
            println("Got key: $key")
            key.verifyJws(token).also { println("VERIFICATION IS: $it") }
        } else {
            CI_TOKEN_KEY.verifyJws(token)
        }
    }.isSuccess

    // -------------------------------------
    // Implementation of abstract issuer service provider interface
    @OptIn(ExperimentalEncodingApi::class)
    override fun generateCredential(credentialRequest: CredentialRequest): CredentialResult {
        println("GENERATING CREDENTIAL:")
        println("Credential request: $credentialRequest")
        println("CREDENTIAL REQUEST JSON -------:")
        println(Json.encodeToString(credentialRequest))

        val jwt = credentialRequest.proof?.jwt ?: throw IllegalArgumentException("No proof.jwt in credential request!")
        val jwtParts = jwt.split(".")

        fun decodeJwtPart(idx: Int) = Json.parseToJsonElement(Base64.decode(jwtParts[idx]).decodeToString()).jsonObject

        val header = decodeJwtPart(0)
        val payload = decodeJwtPart(1)

        val subjectDid =
            header["kid"]?.jsonPrimitive?.contentOrNull ?: throw IllegalArgumentException("No kid in proof.jwt header!")
        val nonce = payload["nonce"]?.jsonPrimitive?.contentOrNull
            ?: throw IllegalArgumentException("No nonce in proof.jwt payload!")


        if (deferIssuance) return CredentialResult(credentialRequest.format, null, randomUUID()).also {
            deferredCredentialRequests[it.credentialId!!] = credentialRequest
        }
        return doGenerateCredential(credentialRequest, subjectDid, nonce)/*.also {
            // for testing purposes: defer next credential if multiple credentials are issued
            deferIssuance = !deferIssuance
        }*/
    }

    override fun getDeferredCredential(credentialID: String): CredentialResult {
        if (deferredCredentialRequests.containsKey(credentialID)) {
            return doGenerateCredential(
                deferredCredentialRequests[credentialID]!!, null, null
            ) // TODO: the null parameters
        }
        throw DeferredCredentialError(CredentialErrorCode.invalid_request, message = "Invalid credential ID given")
    }

    private fun doGenerateCredential(
        credentialRequest: CredentialRequest, subjectDid: String?, nonce: String?
    ): CredentialResult {
        //if (credentialRequest.format == CredentialFormat.mso_mdoc) throw CredentialError(
        //    credentialRequest, CredentialErrorCode.unsupported_credential_format
        //)
        //println("HRVOJE DEBUG TYPES: " + credentialRequest.types)
        //println("HRVOJE DEBUG DEFINITION: " + credentialRequest.credentialDefinition)
        //println("HRVOJE DEBUG REQUEST: " + credentialRequest)
        val types = credentialRequest.types ?: credentialRequest.credentialDefinition?.types ?: throw CredentialError(
            credentialRequest, CredentialErrorCode.unsupported_credential_type
        )
        val proofHeader = credentialRequest.proof?.jwt?.let { parseTokenHeader(it) } ?: throw CredentialError(
            credentialRequest, CredentialErrorCode.invalid_or_missing_proof, message = "Proof must be JWT proof"
        )
        val holderKid = proofHeader[JWTClaims.Header.keyID]?.jsonPrimitive?.content ?: throw CredentialError(
            credentialRequest,
            CredentialErrorCode.invalid_or_missing_proof,
            message = "Proof JWT header must contain kid claim"
        )

        //val vc = W3CVC(universityDegreeCredentialExample.toList().associate { it.first to it.second.toJsonElement() })

        val data: IssuanceSessionData = (if (subjectDid == null || nonce == null) {
            repeat(10) {
                println("WARNING: RETURNING DEMO/EXAMPLE (= BOGUS) CREDENTIAL: subjectDid or nonce is null (was deferred issuance tried?)")
            }
            listOf(
                IssuanceSessionData(
                    exampleIssuerKey,
                    exampleIssuerDid,
                    JwtIssuanceRequest(
                        Json.parseToJsonElement(KeySerialization.serializeKey(exampleIssuerKey)).jsonObject,
                        exampleIssuerDid,
                        W3CVC(openBadgeCredentialExample)
                    )
                )
            )
        } else {
            println("RETRIEVING VC FROM TOKEN MAPPING: $nonce")
            tokenCredentialMapping[nonce]
                ?: throw IllegalArgumentException("The issuanceIdCredentialMapping does not contain a mapping for: $nonce!")
        }).first()

        return CredentialResult(format = credentialRequest.format, credential = JsonPrimitive(runBlocking {
            val vc = data.request.vc

            data.run {
                when (data.request) {
                    is JwtIssuanceRequest -> vc.mergingJwtIssue(
                        issuerKey = issuerKey,
                        issuerDid = issuerDid,
                        subjectDid = holderKid,
                        mappings = request.mapping ?: JsonObject(emptyMap()),
                        additionalJwtHeader = emptyMap(),
                        additionalJwtOptions = emptyMap(),
                    )

                    is SdJwtIssuanceRequest -> vc.mergingSdJwtIssue(
                        issuerKey = issuerKey,
                        issuerDid = issuerDid,
                        subjectDid = holderKid,
                        mappings = request.mapping ?: JsonObject(emptyMap()),
                        additionalJwtHeader = emptyMap(),
                        additionalJwtOptions = emptyMap(),
                        disclosureMap = data.request.selectiveDisclosure ?: SDMap.generateSDMap(
                            JsonObject(emptyMap()),
                            JsonObject(emptyMap())
                        )
                    )

                    is MDLIssuanceRequest -> {
                        println("HRVOJE TEST")
                        println(vc)
                        val completedVC = vc.mergingToVc(
                            issuerDid = issuerDid,
                            subjectDid = holderKid,
                            mappings = request.mapping ?: JsonObject(emptyMap()),
                            true
                        )
                        println("HRVOJE VC INFO: " + completedVC)

                        println("HRVOJE VC INFO: " + completedVC.w3cVc.toJsonObject().get("credentialSubject"))

                        val driversLicense = completedVC.w3cVc.toJsonObject().get("credentialSubject")?.jsonObject?.get("driversLicense")?.jsonObject
                        val document_number = driversLicense?.get("document_number")
                        val family_name = driversLicense?.get("family_name")
                        val given_name = driversLicense?.get("given_name")
                        val portrait = driversLicense?.get("portrait")
                        val birth_date = driversLicense?.get("birth_date")
                        val issue_date = driversLicense?.get("issue_date")
                        val expiry_date = driversLicense?.get("expiry_date")
                        val issuing_country = driversLicense?.get("issuing_country")
                        val issuing_authority = driversLicense?.get("issuing_authority")
                        val driving_privileges = driversLicense?.get("driving_privileges")
                        val age_over_18 = driversLicense?.get("age_over_18")
                        val age_over_21 = driversLicense?.get("age_over_21")
                        val age_over_24 = driversLicense?.get("age_over_24")
                        val age_over_65 = driversLicense?.get("age_over_65")

                        val driving_privileges_json = Json.parseToJsonElement(driving_privileges.toString())
                        println("OVO SU PRIVILEGIJE: " + driving_privileges_json)


                        var driving_privileges_list = listOf<MapElement>()
                        var map: Map<MapKey, StringElement>  = mapOf()

                        driving_privileges_json.jsonArray.forEach { it ->
                            val vehicle_category_code = Pair(
                                MapKey("vehicle_category_code"), StringElement(it.jsonObject?.get("vehicle_category_code")
                                .toString().replace("\"",""))
                            )
                            val issue_date = Pair(MapKey("issue_date"), FullDateElement(LocalDate.parse(it.jsonObject?.get("issue_date").toString().replace("\"",""))))

                            var expiry_date: Pair<MapKey, FullDateElement>? = null

                            if (it.jsonObject?.get("expiry_date").toString().replace("\"","") != "null"){
                                expiry_date = Pair(MapKey("expiry_date"), FullDateElement(LocalDate.parse(it.jsonObject?.get("expiry_date").toString().replace("\"",""))))
                            }

                            println("EXPIRY: " + expiry_date.toString())
                            if (expiry_date != null){
                                driving_privileges_list = driving_privileges_list.plus(MapElement(mapOf(vehicle_category_code, issue_date, expiry_date)))
                            }else{
                                driving_privileges_list = driving_privileges_list.plus(MapElement(mapOf(vehicle_category_code, issue_date)))
                            }

                            println(MapElement(map).toCBORHex())

                            println("IT: " + it.jsonObject?.get("vehicle_category_code"))
                        }

                        println("DRIVING LIST: " + driving_privileges_list)

                        val driving_privileges_list_element  = ListElement(driving_privileges_list)

                        println(driving_privileges_list_element.toCBORHex())

                        println("HRVOJE document_number: " + document_number)
                        println("HRVOJE family_name: " + family_name)
                        println("HRVOJE given_name: " + given_name)
                        println("HRVOJE portrait: " + portrait)
                        println("HRVOJE birth_date: " + birth_date)
                        println("HRVOJE issue_date: " + issue_date)
                        println("HRVOJE expiry_date: " + expiry_date)
                        println("HRVOJE issuing_country: " + issuing_country)
                        println("HRVOJE issuing_authority: " + issuing_authority)
                        println("HRVOJE driving_privileges: " + driving_privileges)
                        println("HRVOJE age_over_18: " + age_over_18)
                        println("HRVOJE age_over_21: " + age_over_21)
                        println("HRVOJE age_over_24: " + age_over_24)
                        println("HRVOJE age_over_65: " + age_over_65)



                        val issuer_ec_key = ECKey.parse(issuerKey.exportJWK())
                        println("HRVOJE ISSUER KEY: " + issuer_ec_key)
                        //println("HRVOJE SUBJECT DID SUB: " +   )
                        val subject_ec_key = ECKey.parse(String(java.util.Base64.getDecoder().decode(subjectDid?.substring(8))))
                        println("HRVOJE SUBJECT KEY: " + subject_ec_key)

                        println("HRVOJE ISSUER CERT CHAIN: " + issuer_ec_key.x509CertChain)
                        var certs: List<X509Certificate> = X509CertChainUtils.parse(issuer_ec_key.x509CertChain)
                        //println("CERTIFICATES: " + certs)

                        // instantiate simple cose crypto provider for issuer keys and certificates
                        val cryptoProvider = SimpleCOSECryptoProvider(
                            listOf(
                                COSECryptoProviderKeyInfo("ISSUER_KEY_ID", AlgorithmID.ECDSA_256, issuer_ec_key.toECPublicKey(), issuer_ec_key.toECPrivateKey(), certs, listOf(certs[2])),
                                COSECryptoProviderKeyInfo("DEVICE_KEY_ID", AlgorithmID.ECDSA_256, subject_ec_key.toECPublicKey()/*, deviceKeyPair.private*/)
                            )
                        )

                        // create device key info structure of device public key, for holder binding
                        val deviceKeyInfo = DeviceKeyInfo(DataElement.fromCBOR(OneKey(subject_ec_key.toECPublicKey(), null).AsCBOR().EncodeToBytes()))

                        // build mdoc and sign using issuer key with holder binding to device key
                        val mdoc = MDocBuilder("org.iso.18013.5.1.mDL")
                            .addItemToSign("org.iso.18013.5.1", "family_name", family_name.toString().replace("\"","").toDE())
                            .addItemToSign("org.iso.18013.5.1", "given_name", given_name.toString().replace("\"","").toDE())
                            .addItemToSign("org.iso.18013.5.1", "portrait", portrait.toString().replace("\"","").toDE())
                            .addItemToSign("org.iso.18013.5.1", "birth_date", FullDateElement(LocalDate.parse(birth_date.toString().replace("\"",""))))
                            .addItemToSign("org.iso.18013.5.1", "issue_date", FullDateElement(LocalDate.parse(issue_date.toString().replace("\"",""))))
                            .addItemToSign("org.iso.18013.5.1", "expiry_date", FullDateElement(LocalDate.parse(expiry_date.toString().replace("\"",""))))
                            .addItemToSign("org.iso.18013.5.1", "issuing_country", issuing_country.toString().replace("\"","").toDE())
                            .addItemToSign("org.iso.18013.5.1", "issuing_authority", issuing_authority.toString().replace("\"","").toDE())
                            .addItemToSign("org.iso.18013.5.1", "age_over_18", BooleanElement(if (age_over_18.toString() == "true") true else false))
                            .addItemToSign("org.iso.18013.5.1", "age_over_21", BooleanElement(if (age_over_21.toString() == "true") true else false))
                            .addItemToSign("org.iso.18013.5.1", "age_over_24", BooleanElement(if (age_over_24.toString() == "true") true else false))
                            .addItemToSign("org.iso.18013.5.1", "age_over_65", BooleanElement(if (age_over_65.toString() == "true") true else false))
                            .addItemToSign("org.iso.18013.5.1", "document_number", document_number.toString().replace("\"","").toDE())
                            //.addItemToSign("org.iso.18013.5.1", "driving_privileges", driving_privileges.toString().replace("\"","").toDE())
                            .addItemToSign("org.iso.18013.5.1", "driving_privileges", driving_privileges_list_element)
                            .sign(
                                ValidityInfo(Clock.System.now(), Clock.System.now(), Clock.System.now().plus(365*24, DateTimeUnit.HOUR)),
                                deviceKeyInfo, cryptoProvider, "ISSUER_KEY_ID"
                            )
                        Cbor.encodeToHexString(mdoc)

                        /*val test5 = SimpleCOSECryptoProvider()
                        val test6 = COSECryptoProviderKeyInfo()
                        val test7 = AlgorithmID.ECDSA_256
                        val test8 = DeviceKeyInfo()
                        val test9 = DataElement.fromCBOR<>()
                        val test10 = MDocBuilder()
                        val test11 = Cbor.encodeToHexString("")
*/
                        //completedVC.run {
                        //    "string2"
                        //}
                        /*vc.mdocIssue(issuerKey = issuerKey,
                            issuerDid = issuerDid,
                            subjectDid = holderKid,
                            mappings = request.mapping ?: JsonObject(emptyMap()),
                            additionalJwtHeader = emptyMap(),
                            disclosureMap = SDMap.generateSDMap(
                                JsonObject(emptyMap()),
                                JsonObject(emptyMap())
                            ),

                            additionalJwtOptions = emptyMap(),
                            )*/

                    }
                }
            }.also { println("Respond VC: $it") }
        }))
    }


    @OptIn(ExperimentalEncodingApi::class)
    override fun generateBatchCredentialResponse(
        batchCredentialRequest: BatchCredentialRequest,
        accessToken: String
    ): BatchCredentialResponse {
        if (batchCredentialRequest.credentialRequests.map { it.format }.distinct().size >= 2) {
            throw IllegalArgumentException("Credential request don't have the same format")
        }

        val keyIdsDistinct = batchCredentialRequest.credentialRequests.map { credReq ->
            credReq.proof?.jwt?.let { jwt -> parseTokenHeader(jwt) }
                ?.get(JWTClaims.Header.keyID)
                ?.jsonPrimitive?.content
                ?: throw CredentialError(
                    credReq,
                    CredentialErrorCode.invalid_or_missing_proof,
                    message = "Proof must be JWT proof"
                )
        }.distinct()

        if (keyIdsDistinct.size >= 2) {
            throw IllegalArgumentException("More than one key id requested")
        }

//        val keyId = keyIdsDistinct.first()




        batchCredentialRequest.credentialRequests.first().let { credentialRequest ->
            val jwt =
                credentialRequest.proof?.jwt ?: throw IllegalArgumentException("No proof.jwt in credential request!")
            val jwtParts = jwt.split(".")

            fun decodeJwtPart(idx: Int) =
                Json.parseToJsonElement(Base64.decode(jwtParts[idx]).decodeToString()).jsonObject

            val header = decodeJwtPart(0)
            val payload = decodeJwtPart(1)

            val subjectDid =
                header["kid"]?.jsonPrimitive?.contentOrNull
                    ?: throw IllegalArgumentException("No kid in proof.jwt header!")
            val nonce = payload["nonce"]?.jsonPrimitive?.contentOrNull
                ?: throw IllegalArgumentException("No nonce in proof.jwt payload!")

            println("RETRIEVING VC FROM TOKEN MAPPING: $nonce")
            val issuanceSessionData = tokenCredentialMapping[nonce]
                ?: throw IllegalArgumentException("The issuanceIdCredentialMapping does not contain a mapping for: $nonce!")

            val credentialResults = issuanceSessionData.map { data ->
                CredentialResponse.success(
                    format = credentialRequest.format,
                    credential = JsonPrimitive(
                        runBlocking {
                            val vc = data.request.vc

                            data.run {
                                when (data.request) {
                                    is JwtIssuanceRequest -> vc.mergingJwtIssue(
                                        issuerKey = issuerKey,
                                        issuerDid = issuerDid,
                                        subjectDid = subjectDid,
                                        mappings = request.mapping ?: JsonObject(emptyMap()),
                                        additionalJwtHeader = emptyMap(),
                                        additionalJwtOptions = emptyMap(),
                                    )

                                    is SdJwtIssuanceRequest -> vc.mergingSdJwtIssue(
                                        issuerKey = issuerKey,
                                        issuerDid = issuerDid,
                                        subjectDid = subjectDid,
                                        mappings = request.mapping ?: JsonObject(emptyMap()),
                                        additionalJwtHeader = emptyMap(),
                                        additionalJwtOptions = emptyMap(),
                                        disclosureMap = data.request.selectiveDisclosure
                                            ?: SDMap.generateSDMap(
                                                JsonObject(emptyMap()),
                                                JsonObject(emptyMap())
                                            )
                                    )

                                    is MDLIssuanceRequest -> TODO()
                                }

                            }.also { println("Respond VC: $it") }
                        }
                    )
                )
            }

            return BatchCredentialResponse.success(credentialResults, accessToken, 5.minutes)
        }
    }


    data class IssuanceSessionData(
        val issuerKey: Key, val issuerDid: String, val request: BaseIssuanceRequest
    )

    // TODO: Hack as this is non stateless because of oidc4vc lib API
    private val sessionCredentialPreMapping = HashMap<String, List<IssuanceSessionData>>() // session id -> VC

    // TODO: Hack as this is non stateless because of oidc4vc lib API
    private val tokenCredentialMapping = HashMap<String, List<IssuanceSessionData>>() // token -> VC

    //private val sessionTokenMapping = HashMap<String, String>() // session id -> token

    // TODO: Hack as this is non stateless because of oidc4vc lib API
    fun setIssuanceDataForIssuanceId(issuanceId: String, data: List<IssuanceSessionData>) {
        println("DEPOSITED CREDENTIAL FOR ISSUANCE ID: $issuanceId")
        sessionCredentialPreMapping[issuanceId] = data
    }

    // TODO: Hack as this is non stateless because of oidc4vc lib API
    fun mapSessionIdToToken(sessionId: String, token: String) {
        println("MAPPING SESSION ID TO TOKEN: $sessionId -->> $token")
        val premappedVc = sessionCredentialPreMapping.remove(sessionId)
            ?: throw IllegalArgumentException("No credential pre-mapped with any such session id: $sessionId (for use with token: $token)")
        println("SWAPPING PRE-MAPPED VC FROM SESSION ID TO NEW TOKEN: $token")
        tokenCredentialMapping[token] = premappedVc
    }
}
