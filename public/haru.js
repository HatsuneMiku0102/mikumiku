document.addEventListener('DOMContentLoaded', function () {
    const personalityCircle = document.getElementById('personalityCircle');
    const personalityPhrase = document.getElementById('personalityPhrase');
    const personalityTextBox = document.getElementById('personalityTextBox');
    const typingSpeed = 120;
    const phraseHoldDuration = 3500;
    let charIndex = 0;
    let typingTimeout;
    let isTyping = false;

    async function getGPTResponse(prompt) {
        const response = await fetch('/api/gpt', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ prompt: prompt })
        });

        const data = await response.json();
        return data;
    }

    function typePhrase(phrase) {
        charIndex = 0;
        personalityPhrase.innerText = "";
        isTyping = true;
        personalityTextBox.classList.add('visible');
        typeNextChar(phrase);
    }

    function typeNextChar(phrase) {
        if (charIndex < phrase.length) {
            personalityPhrase.innerText += phrase[charIndex];
            charIndex++;
            typingTimeout = setTimeout(() => typeNextChar(phrase), typingSpeed);
        } else {
            typingTimeout = setTimeout(() => clearPhrase(), phraseHoldDuration);
        }
    }

    function clearPhrase() {
        personalityPhrase.innerText = "";
        isTyping = false;
        personalityTextBox.classList.remove('visible');
    }

    async function handleUserInput(userPrompt) {
        if (isTyping) return;
        const response = await getGPTResponse(userPrompt);
        typePhrase(response);
    }

    personalityCircle.addEventListener('click', () => {
        const userPrompt = "Tell me something interesting!";
        handleUserInput(userPrompt);
    });
});
