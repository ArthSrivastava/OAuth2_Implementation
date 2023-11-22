package com.example.client.proxy;

import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.service.annotation.GetExchange;

import java.util.Map;

@Component
public interface ResourceServerConsumerClient {

    @GetExchange("/demo")
    String demo(@RequestHeader Map<String, String> headers);
}
