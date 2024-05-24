<script>
document.addEventListener('DOMContentLoaded', function () {
    const textElement = document.getElementById('typing-text');
    const text = 'MikuMiku';
    const delayBetweenWords = 500; 
    const typingSpeed = 200; 

    let index = 0;
    let currentWord = '';

    function typeCharacter() {
        if (index < text.length) {
            currentWord += text[index];
            textElement.innerHTML = currentWord;
            index++;
            setTimeout(typeCharacter, typingSpeed);
        } else if (index === text.length) {
            setTimeout(() => {
                textElement.innerHTML = currentWord + ' ';
                index++;
                setTimeout(typeWord, delayBetweenWords);
            }, typingSpeed);
        }
    }

    function typeWord() {
        if (index < text.length) {
            currentWord = '';
            while (index < text.length && text[index] !== ' ') {
                currentWord += text[index];
                index++;
            }
            index++; 
            textElement.innerHTML = currentWord + ' ';
            setTimeout(typeCharacter, delayBetweenWords);
        }
    }

    typeWord();
});
</script>
