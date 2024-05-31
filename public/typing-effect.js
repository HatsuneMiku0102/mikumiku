document.addEventListener('DOMContentLoaded', function () {
    const typingElements = document.querySelectorAll('.site-title, .fancy-title');
    typingElements.forEach(element => {
        const text = element.textContent;
        element.textContent = '';
        let index = 0;

        function typeCharacter() {
            if (index < text.length) {
                element.textContent += text.charAt(index);
                index++;
                setTimeout(typeCharacter, 150);
            } else {
                element.classList.add('with-caret');
            }
        }

        typeCharacter();
    });
});

const style = document.createElement('style');
style.innerHTML = `
    .with-caret::after {
        content: '|';
        display: inline-block;
        width: 1px;  /* Adjust width to fit the cursor correctly */
        margin-left: 2px; /* Add some space between the text and cursor */
        animation: blink-caret 0.75s step-end infinite;
        color: cyan;
    }

    @keyframes blink-caret {
        0%, 100% {
            opacity: 1;
        }
        50% {
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);
