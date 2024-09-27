document.addEventListener('DOMContentLoaded', function () {
    const personalityCircle = document.getElementById('personalityCircle');
    const personalityPhrase = document.getElementById('personalityPhrase');
    const personalityTextBox = document.getElementById('personalityTextBox'); // Reference to the speech bubble

    const customPhrases = [
        "Hi :)", 
        "How's it going?", 
        "Welcome to MikuMiku.dev", 
        "Feel free to look around.", 
        "What's on your mind today?"
    ];

    let usedPhrases = [];
    let typingIndex = 0;
    let charIndex = 0;
    let typingTimeout;
    let currentPhrase = "";
    let isTyping = false; // Prevent multiple hover triggers
    let isMoodChanging = false; // Prevent mood flickers
    const typingSpeed = 120; // Adjusted typing speed for smoother experience
    const phraseHoldDuration = 3500; // Hold the phrase for a longer duration
    const moodChangeInterval = 12000; // Time between random mood changes

    // Function to select a phrase that hasn't been used recently
    function getRandomPhrase() {
        if (usedPhrases.length >= customPhrases.length) {
            usedPhrases = []; // Reset the used phrases array when all have been used
        }

        let phrase;
        do {
            phrase = customPhrases[Math.floor(Math.random() * customPhrases.length)];
        } while (usedPhrases.includes(phrase));

        usedPhrases.push(phrase);
        return phrase;
    }

    // Function to calculate text width based on content
    function calculateTextWidth(text) {
        const tempSpan = document.createElement('span');
        tempSpan.style.visibility = 'hidden';
        tempSpan.style.whiteSpace = 'nowrap';
        tempSpan.style.fontFamily = window.getComputedStyle(personalityPhrase).fontFamily;
        tempSpan.style.fontSize = window.getComputedStyle(personalityPhrase).fontSize;
        tempSpan.innerText = text;
        document.body.appendChild(tempSpan);
        const textWidth = tempSpan.offsetWidth;
        document.body.removeChild(tempSpan);
        return textWidth;
    }

    // Typing effect with smoother letter spacing and unique form when typing
    function typePhrase(phrase) {
        typingIndex = 0;
        charIndex = 0;
        currentPhrase = phrase;
        personalityPhrase.innerText = ""; // Clear text
        isTyping = true;
        personalityCircle.classList.add('typing'); // Add typing form
        personalityTextBox.classList.add('visible'); // Show speech bubble
        typeNextChar();
    }

    // Function to type the next character and adjust box size
    function typeNextChar() {
        if (charIndex < currentPhrase.length) {
            personalityPhrase.innerText += currentPhrase[charIndex];
            charIndex++;

            // Adjust the width of the text box dynamically based on text length
            const textWidth = calculateTextWidth(personalityPhrase.innerText);
            personalityTextBox.style.width = `${textWidth + 40}px`; // Adjust width dynamically

            typingTimeout = setTimeout(typeNextChar, typingSpeed); // Smooth typing
        } else {
            typingTimeout = setTimeout(clearPhrase, phraseHoldDuration); // Hold the phrase
        }
    }

    // Clear the phrase and reset the typing state
    function clearPhrase() {
        personalityPhrase.innerText = "";
        personalityTextBox.style.width = ""; // Reset the width after clearing
        isTyping = false;
        personalityCircle.classList.remove('typing'); // Remove typing form
        personalityTextBox.classList.remove('visible'); // Hide speech bubble
        changeMood('neutral'); // Reset to neutral after typing
    }

    // Function to dynamically change the shape based on mood
    function changeMood(mood) {
        if (isTyping) return; // Don't change mood while typing
        personalityCircle.className = 'personality-circle'; // Reset shape
        switch (mood) {
            case 'happy':
                personalityCircle.classList.add('personality-happy'); // Happy shape
                break;
            case 'excited':
                personalityCircle.classList.add('personality-excited'); // Excited shape
                break;
            case 'relaxed':
                personalityCircle.classList.add('personality-relaxed'); // Relaxed shape
                break;
            case 'neutral':
            default:
                personalityCircle.classList.add('personality-neutral'); // Default/Neutral shape
                break;
        }
    }

    // Add hover event listeners for widgets and boxes
    const hoverElements = document.querySelectorAll('.box-container, .widget');

    hoverElements.forEach(element => {
        element.addEventListener('mouseenter', () => {
            if (!isTyping) {
                const randomPhrase = getRandomPhrase();
                typePhrase(randomPhrase);
                changeMood('excited');
            }
        });

        element.addEventListener('mouseleave', () => {
            if (!isTyping) {
                setTimeout(() => {
                    changeMood('neutral');
                }, phraseHoldDuration + 500); // Delay to avoid quick mood changes
            }
        });
    });

    // Random mood changes (optional)
    setInterval(() => {
        if (!isTyping) {
            const randomMoods = ['happy', 'relaxed', 'neutral'];
            const randomMood = randomMoods[Math.floor(Math.random() * randomMoods.length)];
            changeMood(randomMood);
        }
    }, moodChangeInterval);

    // Default to neutral mood on page load
    changeMood('neutral');
});
