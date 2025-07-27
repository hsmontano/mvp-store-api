package io.supreme.dev.code.mvpstoreapi.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/products")
public class ProductController {

    @GetMapping()
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String[] getProducts() {
        return new String[] {"Shirts", "Shoes", "Pens", "Socks"};
    }
}
