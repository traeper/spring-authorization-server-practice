package com.traeper.oauth2.authorization

import com.nimbusds.jose.util.Base64
import org.junit.jupiter.api.Test

class ApplicationTests {

    @Test
    fun generateAuthorizationBasicHeader() {
        val clientId = "aaaa"
        val clientSecret = "bbbb"
        val encoded = Base64.encode("$clientId:$clientSecret")
        println(encoded)
    }
}
