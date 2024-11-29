package org.example

import io.ktor.http.*
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.google.gson.Gson
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.example.facades.AuthFacade
import org.example.factories.BCryptValidationStrategy
import org.example.factories.DefaultUserFactory
import org.example.factories.PasswordValidationStrategy
import org.example.factories.UserFactory
import org.example.models.*
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.select
import org.jetbrains.exposed.sql.transactions.transaction
import org.mindrot.jbcrypt.BCrypt
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64
import java.util.Date

// Decrypt function for AES
fun decryptAES(encryptedText: String, key: String, iv: String): String {
    println("Iniciando decriptação AES...")
    val ivSpec = IvParameterSpec(iv.toByteArray())
    val keySpec = SecretKeySpec(key.toByteArray(), "AES")
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
    val decodedBytes = Base64.getDecoder().decode(encryptedText)
    val result = String(cipher.doFinal(decodedBytes))
    println("Decriptação concluída. Resultado: $result")
    return result
}

//Caso precise gerar o Hash para uma senha:
fun generatePasswordHash(rawPassword: String, userIdentifier: String): String {
    val salt = "gate${userIdentifier}keepr"
    val saltedPassword = salt + rawPassword
    val hashedPassword = BCrypt.hashpw(saltedPassword, BCrypt.gensalt())
    println("Salt utilizado: $salt")
    println("Senha original: $rawPassword")
    println("Senha com salt: $saltedPassword")
    println("Hash gerado: $hashedPassword")
    return hashedPassword
}

// Função para configurar a rota de login
fun Routing.loginRoute() {
    val authFacade = AuthFacade(
        jwtSecret = "jwt_secret_key",
        jwtIssuer = "server_framework",
        jwtAudience = "flutter_framework"
    )


    post("/v1/login") {
        println("Recebendo requisição de login...")
        val encryptedContent = call.receive<String>()
        println("Conteúdo criptografado recebido: $encryptedContent")

        val decryptedContent = decryptAES(encryptedContent, "changeit key2024", "1234567890123456")

        val loginRequest = Gson().fromJson(decryptedContent, LoginRequest::class.java)
        val token = authFacade.login(
            userIdentifier = loginRequest.auth.user_identifier,
            rawPassword = loginRequest.auth.user_password,
            domain = loginRequest.domain
        )

//                Caso precise gerar o Hash para uma senha:
//        generatePasswordHash(loginRequest.auth.user_password, loginRequest.auth.user_identifier)

        if (token != null) {
            println("Token gerado: $token")
            call.respond(HttpStatusCode.Created, token)
        } else {
            println("Falha na autenticação. Credenciais ou domínio inválidos.")
            call.respond(HttpStatusCode.Unauthorized, "Invalid credentials or unauthorized access to domain")
        }
    }
}
