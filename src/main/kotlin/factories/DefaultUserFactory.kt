package org.example.factories

import org.example.models.User

class DefaultUserFactory : UserFactory {
    override fun createUser(id: String, username: String, email: String): User {
        println("Criando usuário com Factory")
        return User(id, username, email)
    }
}