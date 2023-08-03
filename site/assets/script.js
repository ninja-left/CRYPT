function copy(id) {
    let code = document.getElementById(id).innerText;
    navigator.clipboard.writeText(code);
}