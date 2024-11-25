package org.example

import io.ktor.http.*
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.google.gson.Gson
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.mindrot.jbcrypt.BCrypt
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64
import java.util.Date

data class LoginRequest(val domain: String, val auth: Auth)
data class Auth(val user_identifier: String, val user_password: String)
data class User(val id: String, val username: String, val email: String)

// Decrypt function for AES
fun decryptAES(encryptedText: String, key: String, iv: String): String {
    val ivSpec = IvParameterSpec(iv.toByteArray())
    val keySpec = SecretKeySpec(key.toByteArray(), "AES")
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
    val decodedBytes = Base64.getDecoder().decode(encryptedText)
    return String(cipher.doFinal(decodedBytes))
}

// Função para buscar usuário no banco de dados
fun findUserInDatabase(userIdentifier: String, hashedPassword: String, domain: String): User? {
    // Exemplo: autenticação e verificação do domínio
    val validHashedPassword = BCrypt.hashpw("senha_sem_hash", "gate${userIdentifier}keepr")
    return if (userIdentifier == "exemplo" && hashedPassword == validHashedPassword && domain == "www.exemplo.com") {
        User(id = "1", username = userIdentifier, email = "user@example.com")
    } else null
}

// Função para configurar a rota de login
fun Routing.loginRoute() {
    post("/v1/login") {
        val encryptedContent = call.receive<String>()
        val decryptedContent = decryptAES(encryptedContent, "change it", "1234567890123456")

        val loginRequest = Gson().fromJson(decryptedContent, LoginRequest::class.java)
        val userIdentifier = loginRequest.auth.user_identifier
        val rawPassword = loginRequest.auth.user_password

        // Gerar hash bcrypt com salt personalizado
        val salt = "gate${userIdentifier}keepr"
        val hashedPassword = BCrypt.hashpw(rawPassword, salt)

        // Simular a busca no banco de dados e verificação de domínio
        val user = findUserInDatabase(userIdentifier, hashedPassword, loginRequest.domain)

        if (user != null) {
            // Gerar JWT com expiração de uma semana
            val token = JWT.create()
                .withAudience("your_audience")
                .withIssuer("your_application")
                .withClaim("userId", user.id)
                .withClaim("username", user.username)
                .withExpiresAt(Date(System.currentTimeMillis() + 7 * 24 * 60 * 60 * 1000)) // Expira em 1 semana
                .sign(Algorithm.HMAC256("jwt_secret_key"))

            call.respond(HttpStatusCode.Created, token)
        } else {
            call.respond(HttpStatusCode.Unauthorized, "Invalid credentials or unauthorized access to domain")
        }
    }
}