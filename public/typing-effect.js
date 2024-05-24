document.addEventListener('DOMContentLoaded', function () {
    const textElement = document.getElementById('typing-text');
    const text = 'MikuMiku';
    const delayBetweenWords = 500; 

    let index = 0;

    function typeWord() {
        if (index < text.length) {
            let currentWord = '';
            while (index < text.length && text[index] !== ' ') {
                currentWord += text[index];
                index++;
            }
            index++; 
            textElement.innerHTML += currentWord + ' ';
            setTimeout(typeWord, delayBetweenWords);
        }
    }

    typeWord();
});
