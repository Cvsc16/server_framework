package org.example.db

import org.jetbrains.exposed.sql.Database

object DatabaseFactory {
    fun init() {
        Database.connect(
            url = "jdbc:mysql://localhost:3306/framework_software_db",
            driver = "com.mysql.cj.jdbc.Driver",
            user = "root",
            password = "framework"
        )
    }
}
