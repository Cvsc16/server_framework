package org.example.models

import org.jetbrains.exposed.sql.Table

object Domains : Table("domains_tbl") {
    val id = integer("id").autoIncrement()
    val domain = varchar("domain", 200)

    override val primaryKey = PrimaryKey(id)
}