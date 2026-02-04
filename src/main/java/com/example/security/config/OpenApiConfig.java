package com.example.security.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI/Swagger Configuration.
 *
 * Configures API documentation with JWT bearer authentication.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Spring Security JWT Demo API")
                        .version("1.0.0")
                        .description("""
                            REST API with JWT Authentication.

                            ## Authentication

                            1. Register a new user: `POST /api/auth/register`
                            2. Login to get token: `POST /api/auth/login`
                            3. Use the token in the Authorization header: `Bearer <token>`

                            ## Roles

                            - **USER**: Can access user endpoints
                            - **ADMIN**: Can access all endpoints including admin
                            """)
                        .contact(new Contact()
                                .name("Demo API")
                                .email("demo@example.com")))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("Enter JWT token")));
    }
}
