package org.example

import io.ktor.http.*
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.google.gson.Gson
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
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

// Função para verificar senha com base no banco
fun isPasswordValid(rawPassword: String, userIdentifier: String, hashedPasswordFromDB: String): Boolean {
    val salt = "gate${userIdentifier}keepr"
    val saltedPassword = salt + rawPassword
    println("Verificando senha para o usuário: $userIdentifier")
    println("Salt gerado: $salt")
    println("Senha concatenada com salt: $saltedPassword")
    println("Hash armazenado no banco: $hashedPasswordFromDB")
    val isValid = BCrypt.checkpw(saltedPassword, hashedPasswordFromDB)
    println("Resultado da verificação de senha: $isValid")
    return isValid
}

// Ajuste da função para buscar o usuário no banco
fun findUserInDatabase(userIdentifier: String, rawPassword: String, domain: String): User? {
    println("Buscando usuário no banco...")
    return transaction {
        val user = Users.select { Users.identifier eq userIdentifier }.singleOrNull()

        if (user != null) {
            println("Usuário encontrado: ${user[Users.identifier]}")
            val hashedPasswordFromDB = user[Users.passwordHash]
            val isPasswordCorrect = isPasswordValid(rawPassword, userIdentifier, hashedPasswordFromDB)

            if (isPasswordCorrect) {
                println("Senha válida. Verificando domínio associado...")
                val domainExists = UsersDomains
                    .innerJoin(Domains)
                    .select {
                        (UsersDomains.userId eq user[Users.id]) and (Domains.domain eq domain)
                    }
                    .count() > 0

                if (domainExists) {
                    println("Domínio válido: $domain")
                    return@transaction User(
                        id = user[Users.id].toString(),
                        username = user[Users.identifier],
                        email = "user@example.com"
                    )
                } else {
                    println("Domínio inválido: $domain")
                }
            } else {
                println("Senha inválida para o usuário: $userIdentifier")
            }
        } else {
            println("Usuário não encontrado: $userIdentifier")
        }

        null
    }
}

// Função para configurar a rota de login
fun Routing.loginRoute() {
    post("/v1/login") {
        println("Recebendo requisição de login...")
        val encryptedContent = call.receive<String>()
        println("Conteúdo criptografado recebido: $encryptedContent")

        val decryptedContent = decryptAES(encryptedContent, "changeit key2024", "1234567890123456")

        val loginRequest = Gson().fromJson(decryptedContent, LoginRequest::class.java)
        val userIdentifier = loginRequest.auth.user_identifier
        val rawPassword = loginRequest.auth.user_password
        val domain = loginRequest.domain

//        Caso precise gerar o Hash para uma senha:
//        generatePasswordHash(rawPassword, userIdentifier)

        println("Iniciando validação para o usuário: $userIdentifier no domínio: $domain")

        val user = findUserInDatabase(userIdentifier, rawPassword, domain)

        if (user != null) {
            println("Usuário validado com sucesso. Gerando token JWT...")
            val token = JWT.create()
                .withAudience("flutter_framework")
                .withIssuer("server_framework")
                .withClaim("userId", user.id)
                .withClaim("username", user.username)
                .withExpiresAt(Date(System.currentTimeMillis() + 7 * 24 * 60 * 60 * 1000)) // Expira em 1 semana
                .sign(Algorithm.HMAC256("jwt_secret_key"))

            println("Token gerado: $token")
            call.respond(HttpStatusCode.Created, token)
        } else {
            println("Falha na autenticação. Credenciais ou domínio inválidos.")
            call.respond(HttpStatusCode.Unauthorized, "Invalid credentials or unauthorized access to domain")
        }
    }
}
