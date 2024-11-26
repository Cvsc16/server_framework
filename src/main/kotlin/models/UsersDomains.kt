package org.example.models

import org.jetbrains.exposed.sql.Table

object UsersDomains : Table("users_domains_tbl") {
    val id = integer("id").autoIncrement()
    val userId = integer("user_id").references(Users.id)
    val domainId = integer("domain_id").references(Domains.id)

    override val primaryKey = PrimaryKey(id)
}