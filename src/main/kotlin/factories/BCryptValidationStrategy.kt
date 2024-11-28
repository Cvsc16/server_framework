package org.example.factories

import org.mindrot.jbcrypt.BCrypt

class BCryptValidationStrategy : PasswordValidationStrategy {
    override fun isValid(rawPassword: String, userIdentifier: String, hashedPassword: String): Boolean {
        val salt = "gate${userIdentifier}keepr"
        val saltedPassword = salt + rawPassword
        println("Salt utilizado: $salt")
        println("Senha original: $rawPassword")
        println("Senha com salt: $saltedPassword")
        println("Hash gerado: $hashedPassword")
        println("Validando senha com BCrypt para $userIdentifier")
        return BCrypt.checkpw(saltedPassword, hashedPassword)
    }
}