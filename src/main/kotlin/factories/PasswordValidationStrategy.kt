package org.example.factories

interface PasswordValidationStrategy {
    fun isValid(rawPassword: String, userIdentifier: String, hashedPassword: String): Boolean
}