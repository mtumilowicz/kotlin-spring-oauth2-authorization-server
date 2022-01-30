package com.example.app

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.test.web.servlet.MockMvc
import spock.lang.Specification

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationServerTest extends Specification {

    @Autowired
    private MockMvc mvc

    @WithMockUser
    def 'authorized'() {
        expect:
        mvc.perform(get('/oauth/authorize?response_type=code&client_id=client&scope=read'))
                .andExpect(status().isOk())
    }

    @WithMockUser
    def 'not authorized - wrong client id'() {
        expect:
        mvc.perform(get('/oauth/authorize?response_type=code&client_id=client2&scope=read'))
                .andExpect(status().isUnauthorized())
    }

    def 'not authorized - no user'() {
        expect:
        mvc.perform(get('/oauth/authorize?response_type=code&client_id=client2&scope=read'))
                .andExpect(status().isUnauthorized())
    }
}
