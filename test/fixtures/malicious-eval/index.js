// Malicious package that uses eval()
const code = "console.log('executed')";
eval(code);
