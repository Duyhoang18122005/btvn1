package com.example.demo_jwt.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("api/v1/product")
public class ProductController {
    @GetMapping("/list")
    public List<String> ProductList(){
        List<String> productList = new ArrayList<>();
        productList.add("iPhone 15");
        productList.add("iPhone 16");
        return productList;
    }
}
