package com.example.jwtsecurity.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration class for Swagger/OpenAPI.  This configures Swagger to use a Bearer authentication scheme for JWT.
 */
@Configuration
public class SwaggerConfig {

    /**
     * Creates a custom OpenAPI bean that defines a Bearer authentication scheme for JWT.
     * @return The custom OpenAPI object.
     */
    @Bean
    public io.swagger.v3.oas.models.OpenAPI customOpenAPI() {
        return new io.swagger.v3.oas.models.OpenAPI()
                .components(new Components().addSecuritySchemes("bearerAuth",
                        new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                ))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"));
    }
}
