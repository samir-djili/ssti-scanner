package com.ssti.test.freemarker;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.*;

/**
 * Vulnerable FreeMarker Spring application for SSTI testing.
 *
 * This application contains intentionally vulnerable endpoints to test SSTI detection.
 * DO NOT use this code in production environments.
 */
@SpringBootApplication
@Controller
public class FreeMarkerSSTIApp {

    private Configuration freemarkerConfig;
    
    public static void main(String[] args) {
        System.out.println("Starting FreeMarker SSTI Test Application");
        System.out.println("WARNING: This application contains intentional vulnerabilities!");
        System.out.println("Available endpoints:");
        System.out.println("  http://localhost:8082/ - Main page");
        System.out.println("  http://localhost:8082/search?q=${7*7} - Search test");
        System.out.println("  http://localhost:8082/profile - Profile form");
        System.out.println("  http://localhost:8082/render?content=${\"test\".getClass()} - Direct render");
        System.out.println("  http://localhost:8082/debug?msg=${product.getClass()} - Debug page");
        System.out.println("  http://localhost:8082/api/eval?expr=${7*7} - API evaluation");
        
        SpringApplication.run(FreeMarkerSSTIApp.class, args);
    }
    
    public FreeMarkerSSTIApp() {
        initializeFreeMarker();
    }
    
    private void initializeFreeMarker() {
        freemarkerConfig = new Configuration(Configuration.VERSION_2_3_31);
        freemarkerConfig.setClassForTemplateLoading(this.getClass(), "/");
        freemarkerConfig.setDefaultEncoding("UTF-8");
        
        // Enable dangerous features for testing
        freemarkerConfig.setNewBuiltinClassResolver(freemarker.template.utility.Constants.SAFER_RESOLVER);
        freemarkerConfig.setLogTemplateExceptions(true);
        freemarkerConfig.setWrapUncheckedExceptions(true);
    }
    
    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("title", "FreeMarker SSTI Test App");
        return "index";
    }
    
    @GetMapping("/search")
    public void search(@RequestParam(defaultValue = "default") String q, 
                      HttpServletResponse response) throws Exception {
        
        // VULNERABLE: Direct template processing with user input
        String templateString = """
            <html>
            <head><title>Search Results</title></head>
            <body>
                <h1>Search Results</h1>
                <p>You searched for: ${query}</p>
                <div class="results">
                    <p>Query length: ${query?length}</p>
                    <p>Query uppercase: ${query?upper_case}</p>
                    <p>Math test: ${7*7}</p>
                </div>
            </body>
            </html>
            """;
        
        processTemplate(templateString, Map.of("query", q), response);
    }
    
    @GetMapping("/profile")
    public String profileForm() {
        return "profile_form";
    }
    
    @PostMapping("/profile")
    public void profileSubmit(@RequestParam String name,
                             @RequestParam String bio,
                             @RequestParam String signature,
                             HttpServletResponse response) throws Exception {
        
        // VULNERABLE: Form data in template
        String templateString = """
            <html>
            <body>
                <h1>Profile Updated</h1>
                <div class="profile">
                    <h2>${name}</h2>
                    <div class="bio">${bio}</div>
                    <div class="signature">${signature}</div>
                </div>
                <p>Java Version: ${.version}</p>
                <p>Template Name: ${.template_name}</p>
            </body>
            </html>
            """;
        
        Map<String, Object> model = new HashMap<>();
        model.put("name", name);
        model.put("bio", bio);
        model.put("signature", signature);
        
        processTemplate(templateString, model, response);
    }
    
    @GetMapping("/render")
    public void directRender(@RequestParam(defaultValue = "hello") String content,
                            @RequestParam(defaultValue = "simple") String type,
                            HttpServletResponse response) throws Exception {
        
        String templateString;
        
        // VULNERABLE: Building template from user input
        switch (type) {
            case "class":
                templateString = "<h1>Class Test</h1><p>Content: " + content + "</p><p>Class: ${\"\"?class}</p>";
                break;
            case "object":
                templateString = "<h1>Object Test</h1><p>Content: " + content + "</p><p>Object: ${.data_model}</p>";
                break;
            case "version":
                templateString = "<h1>Version Test</h1><p>Content: " + content + "</p><p>Version: ${.version}</p>";
                break;
            default:
                templateString = "<h1>Simple</h1><p>${content}</p>";
        }
        
        processTemplate(templateString, Map.of("content", content), response);
    }
    
    @GetMapping("/debug")
    public void debugPage(@RequestParam(defaultValue = "no message") String msg,
                         @RequestParam(defaultValue = "basic") String level,
                         HttpServletResponse response) throws Exception {
        
        // VULNERABLE: Debug information exposure
        String templateString;
        if ("advanced".equals(level)) {
            templateString = """
                <h1>Advanced Debug</h1>
                <p>Message: ${message}</p>
                <div class="debug">
                    <h2>Template Info:</h2>
                    <p>Version: ${.version}</p>
                    <p>Template Name: ${.template_name}</p>
                    <p>Data Model: ${.data_model}</p>
                    <h2>Java Info:</h2>
                    <p>Class: ${"".getClass()}</p>
                    <p>Class Name: ${"".getClass().getName()}</p>
                </div>
                """;
        } else {
            templateString = """
                <h1>Basic Debug</h1>
                <p>Message: ${message}</p>
                <p>Template: ${.template_name}</p>
                """;
        }
        
        processTemplate(templateString, Map.of("message", msg), response);
    }
    
    @GetMapping("/api/eval")
    @ResponseBody
    public Map<String, Object> apiEval(@RequestParam(defaultValue = "1+1") String expr,
                                      @RequestParam(defaultValue = "json") String format) throws Exception {
        
        // VULNERABLE: Expression evaluation in API
        String templateString = "Result: ${" + expr + "}";
        
        StringWriter writer = new StringWriter();
        Template template = new Template("api", new StringReader(templateString), freemarkerConfig);
        template.process(new HashMap<>(), writer);
        
        String result = writer.toString();
        
        Map<String, Object> response = new HashMap<>();
        response.put("expression", expr);
        response.put("result", result);
        response.put("status", "success");
        
        return response;
    }
    
    @GetMapping("/class")
    public void classExploration(@RequestParam(defaultValue = "java.lang.String") String className,
                                HttpServletResponse response) throws Exception {
        
        // VULNERABLE: Class exploration
        String templateString = """
            <h1>Class Exploration</h1>
            <p>Class Name: ${className}</p>
            <p>For Name: ${className?eval}</p>
            <p>String Class: ${"".getClass()}</p>
            <p>String Class Name: ${"".getClass().getName()}</p>
            """;
        
        processTemplate(templateString, Map.of("className", className), response);
    }
    
    @GetMapping("/object")
    public void objectAccess(@RequestParam(defaultValue = "test") String input,
                            HttpServletResponse response) throws Exception {
        
        // VULNERABLE: Object model access
        String templateString = """
            <h1>Object Access</h1>
            <p>Input: ${input}</p>
            <p>Data Model: ${.data_model}</p>
            <p>Globals: ${.globals}</p>
            <p>Variables: ${.variables}</p>
            """;
        
        Map<String, Object> model = new HashMap<>();
        model.put("input", input);
        model.put("product", new TestProduct("Test Product", 100));
        
        processTemplate(templateString, model, response);
    }
    
    @GetMapping("/builtin")
    public void builtinAccess(@RequestParam(defaultValue = "test") String value,
                             HttpServletResponse response) throws Exception {
        
        // VULNERABLE: Built-in access
        String templateString = """
            <h1>Built-in Access</h1>
            <p>Value: ${value}</p>
            <p>Value Class: ${value.getClass()}</p>
            <p>Value Class Name: ${value.getClass().getName()}</p>
            <p>Class for Name: ${value.getClass().forName("java.lang.Runtime")}</p>
            """;
        
        processTemplate(templateString, Map.of("value", value), response);
    }
    
    @GetMapping("/new")
    public void newOperator(@RequestParam(defaultValue = "java.util.ArrayList") String className,
                           HttpServletResponse response) throws Exception {
        
        // VULNERABLE: NEW operator usage
        String templateString = """
            <h1>NEW Operator Test</h1>
            <p>Class: ${className}</p>
            <p>New Instance: ${className?eval?new()}</p>
            <p>ArrayList: ${"java.util.ArrayList"?eval?new()}</p>
            """;
        
        processTemplate(templateString, Map.of("className", className), response);
    }
    
    @GetMapping("/static")
    public void staticAccess(@RequestParam(defaultValue = "java.lang.System") String className,
                            @RequestParam(defaultValue = "getProperty") String method,
                            HttpServletResponse response) throws Exception {
        
        // VULNERABLE: Static method access
        String templateString = """
            <h1>Static Access</h1>
            <p>Class: ${className}</p>
            <p>Method: ${method}</p>
            <p>System Property: ${statics["java.lang.System"].getProperty("java.version")}</p>
            """;
        
        Map<String, Object> model = new HashMap<>();
        model.put("className", className);
        model.put("method", method);
        model.put("statics", freemarker.template.utility.StaticsModel.class);
        
        processTemplate(templateString, model, response);
    }
    
    private void processTemplate(String templateString, Map<String, Object> model, 
                               HttpServletResponse response) throws IOException, TemplateException {
        
        Template template = new Template("dynamic", new StringReader(templateString), freemarkerConfig);
        
        response.setContentType("text/html");
        PrintWriter writer = response.getWriter();
        
        try {
            template.process(model, writer);
        } catch (Exception e) {
            writer.println("<h1>Template Error</h1>");
            writer.println("<p>Error: " + e.getMessage() + "</p>");
            writer.println("<pre>" + e.getClass().getName() + "</pre>");
        }
        
        writer.flush();
    }
    
    // Test class for object access
    public static class TestProduct {
        private String name;
        private int price;
        
        public TestProduct(String name, int price) {
            this.name = name;
            this.price = price;
        }
        
        public String getName() { return name; }
        public int getPrice() { return price; }
        public Class<?> getClass() { return TestProduct.class; }
        
        // Dangerous method for testing
        public String executeCommand(String cmd) {
            try {
                Process process = Runtime.getRuntime().exec(cmd);
                Scanner scanner = new Scanner(process.getInputStream());
                StringBuilder result = new StringBuilder();
                while (scanner.hasNextLine()) {
                    result.append(scanner.nextLine()).append("\n");
                }
                return result.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
}
