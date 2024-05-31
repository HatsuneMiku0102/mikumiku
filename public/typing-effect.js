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
                const blinkCaret = document.createElement('span');
                blinkCaret.classList.add('blink-caret');
                blinkCaret.textContent = '\u200B'; 
                element.appendChild(blinkCaret);
            }
        }

        typeCharacter();
    });
});

const style = document.createElement('style');
style.innerHTML = `
    .blink-caret {
        display: inline-block;
        width: 2px;
        height: 1em;
        background-color: cyan;
        animation: blink-caret 0.75s step-end infinite;
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
