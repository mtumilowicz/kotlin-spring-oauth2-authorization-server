package com.example.app

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication


@SpringBootApplication
class OauthPlaygroundApplication

fun main(args: Array<String>) {
    runApplication<OauthPlaygroundApplication>(*args)
}