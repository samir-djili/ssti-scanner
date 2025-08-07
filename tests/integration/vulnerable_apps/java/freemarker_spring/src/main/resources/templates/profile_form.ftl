<!DOCTYPE html>
<html>
<body>
    <h1>Update Profile</h1>
    <form method="post" action="/profile">
        <label>Name:</label><br>
        <input type="text" name="name" value="User"><br><br>
        <label>Bio:</label><br>
        <textarea name="bio" rows="4" cols="50">Enter bio...</textarea><br><br>
        <label>Signature:</label><br>
        <input type="text" name="signature" value="Best regards"><br><br>
        <input type="submit" value="Update">
    </form>
</body>
</html>
