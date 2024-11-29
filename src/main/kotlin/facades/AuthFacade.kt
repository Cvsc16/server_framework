package org.example.facades

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import org.example.factories.BCryptValidationStrategy
import org.example.factories.DefaultUserFactory
import org.example.models.Domains
import org.example.models.User
import org.example.models.Users
import org.example.models.UsersDomains
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.select
import org.jetbrains.exposed.sql.transactions.transaction
import java.util.*

class AuthFacade(
    private val jwtSecret: String,
    private val jwtIssuer: String,
    private val jwtAudience: String
) {
    private val passwordValidationStrategy = BCryptValidationStrategy()
    private val userFactory = DefaultUserFactory()

    fun login(userIdentifier: String, rawPassword: String, domain: String): String? {
        println("Iniciando validação para o usuário: $userIdentifier no domínio: $domain")
        val user = findUserInDatabase(userIdentifier, rawPassword, domain) ?: return null
        return generateToken(user)
    }

    private fun findUserInDatabase(userIdentifier: String, rawPassword: String, domain: String): User? {
        println("Buscando usuário no banco...")
        return transaction {
            val userRow = Users.select { Users.identifier eq userIdentifier }.singleOrNull()

            if (userRow != null) {
                println("Usuário encontrado: ${userRow[Users.identifier]}")
                val hashedPassword = userRow[Users.passwordHash]
                val isPasswordCorrect = passwordValidationStrategy.isValid(
                    rawPassword,
                    userIdentifier,
                    hashedPassword
                )

                if (isPasswordCorrect) {
                    println("Senha válida. Verificando domínio associado...")
                    val domainExists = UsersDomains
                        .innerJoin(Domains)
                        .select {
                            (UsersDomains.userId eq userRow[Users.id]) and (Domains.domain eq domain)
                        }
                        .count() > 0

                    if (domainExists) {
                        println("Domínio válido: $domain")
                        return@transaction userFactory.createUser(
                            id = userRow[Users.id].toString(),
                            username = userRow[Users.identifier],
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

    private fun generateToken(user: User): String {
        println("Usuário validado com sucesso. Gerando token JWT...")
        return JWT.create()
            .withAudience(jwtAudience)
            .withIssuer(jwtIssuer)
            .withClaim("userId", user.id)
            .withClaim("username", user.username)
            .withExpiresAt(Date(System.currentTimeMillis() + 7 * 24 * 60 * 60 * 1000)) // 1 semana
            .sign(Algorithm.HMAC256(jwtSecret))
    }
}
