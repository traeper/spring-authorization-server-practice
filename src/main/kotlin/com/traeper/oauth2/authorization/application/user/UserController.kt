package com.traeper.oauth2.authorization.application.user

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RequestMapping("/v1/users")
@RestController
class UserController {

    @GetMapping("/me")
    fun getMyInfo(): UserInfoResponse =
        UserInfoResponse("traeper")

    data class UserInfoResponse(
        val nickname: String,
    )
}
