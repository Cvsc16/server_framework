package org.example.factories

import org.example.models.User

interface UserFactory {
    fun createUser(id: String, username: String, email: String): User
}