package com.example.client.config;

import com.example.client.proxy.ResourceServerConsumerClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.support.WebClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import java.time.Duration;

@Configuration
public class WebConfig {

    @Bean
    public ResourceServerConsumerClient resourceServerConsumerClient() {
        WebClient client = WebClient.builder()
                .baseUrl("http://localhost:9090").build();
        HttpServiceProxyFactory factory = HttpServiceProxyFactory
                .builder(WebClientAdapter.forClient(client))
                .blockTimeout(Duration.ofSeconds(7))
                .build();
        return factory.createClient(ResourceServerConsumerClient.class);
    }
}
