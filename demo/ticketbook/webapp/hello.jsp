<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Hello</title>
</head>
<body>

<form>
  <div>Enter name:</div>
  <input name="name">
  <button name="submit" type="submit">Submit</button>
</form>

<h1>Hello, ${param.name}!</h1>

</body>
</html>
