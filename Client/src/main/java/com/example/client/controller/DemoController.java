package com.example.client.controller;

import com.example.client.service.ResourceServerConsumerService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class DemoController {

    private final ResourceServerConsumerService resourceServerConsumerService;

    @GetMapping("/data")
    public String data() {
        return resourceServerConsumerService.getData();
    }

}
