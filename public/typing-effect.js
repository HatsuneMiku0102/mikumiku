document.addEventListener('DOMContentLoaded', function () {
    const textElement = document.getElementById('typing-text');
    const text = 'MikuMiku';
    const typingSpeed = 200;

    let index = 0;
    
    // Clear the text content before starting the typing animation
    textElement.innerHTML = '';

    function typeCharacter() {
        if (index < text.length) {
            textElement.innerHTML += text[index];
            index++;
            setTimeout(typeCharacter, typingSpeed);
        }
    }

    typeCharacter();
});
