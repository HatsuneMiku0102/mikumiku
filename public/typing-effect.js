document.addEventListener('DOMContentLoaded', function () {
    const textElement = document.getElementById('typing-text');
    const text = 'MikuMiku';
    const delayBetweenWords = 500; // Delay in milliseconds between words

    let index = 0;

    function typeWord() {
        if (index < text.length) {
            let currentWord = '';
            while (index < text.length && text[index] !== ' ') {
                currentWord += text[index];
                index++;
            }
            index++; // Skip the space character
            textElement.innerHTML += currentWord + ' ';
            setTimeout(typeWord, delayBetweenWords);
        }
    }

    typeWord();
});