package org.example.models

import org.jetbrains.exposed.sql.Table

object Users : Table("users_tbl") {
    val id = integer("id").autoIncrement()
    val identifier = varchar("identifier", 50)
    val passwordHash = varchar("password_hash", 64)

    override val primaryKey = PrimaryKey(id)
}