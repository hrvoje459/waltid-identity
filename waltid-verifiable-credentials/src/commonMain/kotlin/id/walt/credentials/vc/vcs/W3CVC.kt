package id.walt.credentials.vc.vcs

import id.walt.credentials.schemes.JwsSignatureScheme
import id.walt.credentials.schemes.JwsSignatureScheme.JwsHeader
import id.walt.credentials.schemes.JwsSignatureScheme.JwsOption
import id.walt.crypto.keys.Key
import id.walt.crypto.utils.JsonUtils.toJsonElement
import id.walt.mdoc.dataelement.FullDateElement
import id.walt.sdjwt.SDJwt
import id.walt.sdjwt.SDMap
import id.walt.sdjwt.SDPayload
import io.ktor.utils.io.core.*
import kotlinx.datetime.LocalDate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToString
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*
import love.forte.plugin.suspendtrans.annotation.JsPromise
import love.forte.plugin.suspendtrans.annotation.JvmAsync
import love.forte.plugin.suspendtrans.annotation.JvmBlocking
import kotlin.js.ExperimentalJsExport
import kotlin.js.JsExport

//import com.nimbusds.jose.jwk.ECKey


@OptIn(ExperimentalJsExport::class)
@JsExport
class W3CVCSerializer : KSerializer<W3CVC> {
    override val descriptor: SerialDescriptor = JsonObject.serializer().descriptor
    override fun deserialize(decoder: Decoder): W3CVC = W3CVC(decoder.decodeSerializableValue(JsonObject.serializer()))
    override fun serialize(encoder: Encoder, value: W3CVC) = encoder.encodeSerializableValue(JsonObject.serializer(), value.toJsonObject())
}

@OptIn(ExperimentalJsExport::class)
@JsExport
@Serializable(with = W3CVCSerializer::class)
data class W3CVC(
    private val content: Map<String, JsonElement> = emptyMap()
) : Map<String, JsonElement> by content {


    fun toJsonObject(): JsonObject = JsonObject(content)
    fun toJson(): String = Json.encodeToString(content)
    fun toPrettyJson(): String = prettyJson.encodeToString(content)

    @JvmBlocking
    @JvmAsync
    @JsPromise
    @JsExport.Ignore
    suspend fun signSdJwt(
        issuerKey: Key,
        issuerDid: String,
        subjectDid: String,
        disclosureMap: SDMap,
        /** Set additional options in the JWT header */
        additionalJwtHeader: Map<String, String> = emptyMap(),
        /** Set additional options in the JWT payload */
        additionalJwtOptions: Map<String, JsonElement> = emptyMap()
    ): String {
        val vc = this.toJsonObject()

        val sdPayload = SDPayload.createSDPayload(vc, disclosureMap)
        val signable = Json.encodeToString(sdPayload.undisclosedPayload).toByteArray()

        val signed = issuerKey.signJws(
            signable, mapOf(
                "typ" to "vc+sd-jwt",
                "cty" to "credential-claims-set+json",
                "kid" to issuerDid
            )
        )

        return SDJwt.createFromSignedJwt(signed, sdPayload).toString()
    }
    @JvmBlocking
    @JvmAsync
    @JsPromise
    @JsExport.Ignore
    suspend fun signJws(
        issuerKey: Key,
        issuerDid: String,
        subjectDid: String,
        /** Set additional options in the JWT header */
        additionalJwtHeader: Map<String, String> = emptyMap(),
        /** Set additional options in the JWT payload */
        additionalJwtOptions: Map<String, JsonElement> = emptyMap()
    ): String {
        return JwsSignatureScheme().sign(
            data = this.toJsonObject(),
            key = issuerKey,
            jwtHeaders = mapOf(
                JwsHeader.KEY_ID to issuerDid,
                *(additionalJwtHeader.entries.map { it.toPair() }.toTypedArray())
            ),
            jwtOptions = mapOf(
                JwsOption.ISSUER to JsonPrimitive(issuerDid),
                JwsOption.SUBJECT to JsonPrimitive(subjectDid),
                *(additionalJwtOptions.entries.map { it.toPair() }.toTypedArray())
            ),
        )
    }
    @JvmBlocking
    @JvmAsync
    @JsPromise
    @JsExport.Ignore
    suspend fun signMDoc(
        issuerKey: Key,
        issuerDid: String,
        subjectDid: String,
        /** Set additional options in the JWT header */
        additionalJwtHeader: Map<String, String> = emptyMap(),
        /** Set additional options in the JWT payload */
        additionalJwtOptions: Map<String, JsonElement> = emptyMap()
    ): String {
        //println("HRVOJE ISSUER JWK: " + issuerKey.exportJWK())
        //println("HRVOJE ISSUER DID: " + issuerDid)
        //println("HRVOJE SUBJECT DID: " + subjectDid)
        //println("HRVOJE ADDITIONAL JWT HEADERS: " + additionalJwtHeader)
        //println("HRVOJE ADDITIONAL JWT OPTIONS: " + additionalJwtOptions)
        //println("HRVOJE CONTENT: " + content)

        //val issuer_EC = ECKey.parse(issuerKey.exportJWK())

        //println("HRVOJE SUBJECT: " + content["credentialSubject"].toJsonElement().jsonObject.entries.filter { it.key == "driversLicense" }.last().value  )

        //val testFDE = FullDateElement(LocalDate(1990, 1, 15))
        //println("HRVOJE FDE: " + testFDE.toString())

        // instantiate simple cose crypto provider for issuer keys and certificates
        /*val cryptoProvider = SimpleCOSECryptoProvider(
            listOf(
                COSECryptoProviderKeyInfo(ISSUER_KEY_ID, AlgorithmID.ECDSA_256, issuerKeyPair.public, issuerKeyPair.private, listOf(issuerCertificate), listOf(rootCaCertificate)),
                COSECryptoProviderKeyInfo(DEVICE_KEY_ID, AlgorithmID.ECDSA_256, deviceKeyPair.public/*, deviceKeyPair.private*/)
            )
        )

        // build mdoc and sign using issuer key with holder binding to device key
        val mdoc = MDocBuilder("org.iso.18013.5.1.mDL")
            .addItemToSign("org.iso.18013.5.1", "family_name", "Doe".toDE())
            .addItemToSign("org.iso.18013.5.1", "given_name", "John".toDE())
            .addItemToSign("org.iso.18013.5.1", "birth_date", FullDateElement(LocalDate(1990, 1, 15)))
            .addItemToSign("org.iso.18013.5.1", "gender", "Male".toDE())
            .sign(
                ValidityInfo(Clock.System.now(), Clock.System.now(), Clock.System.now().plus(365*24, DateTimeUnit.HOUR)),
                deviceKeyInfo, cryptoProvider, ISSUER_KEY_ID
            )
*/



        return  "can't generate mdoc from here"


        /*return JwsSignatureScheme().sign(
            data = this.toJsonObject(),
            key = issuerKey,
            jwtHeaders = mapOf(
                JwsHeader.KEY_ID to issuerDid,
                *(additionalJwtHeader.entries.map { it.toPair() }.toTypedArray())
            ),
            jwtOptions = mapOf(
                JwsOption.ISSUER to JsonPrimitive(issuerDid),
                JwsOption.SUBJECT to JsonPrimitive(subjectDid),
                *(additionalJwtOptions.entries.map { it.toPair() }.toTypedArray())
            ),
        )*/
    }

    companion object {
        fun build(
            context: List<String>,
            type: List<String>,
            vararg data: Pair<String, Any>
        ): W3CVC {
            return W3CVC(
                mutableMapOf(
                    "@context" to context.toJsonElement(),
                    "type" to type.toJsonElement()
                ).apply { putAll(data.toMap().mapValues { it.value.toJsonElement() }) }
            )
        }


        fun fromJson(json: String) =
            W3CVC(Json.decodeFromString<Map<String, JsonElement>>(json))

        private val prettyJson = Json { prettyPrint = true }
    }

}
