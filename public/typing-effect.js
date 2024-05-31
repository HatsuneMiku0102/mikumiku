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
                element.appendChild(blinkCaret);
            }
        }

        typeCharacter();
    });
});

const style = document.createElement('style');
style.innerHTML = `
    .blink-caret {
        border-right: 0.15em solid cyan;
        animation: blink-caret 0.75s step-end infinite;
    }
    @keyframes blink-caret {
        from, to {
            border-color: transparent;
        }
        50% {
            border-color: cyan;
        }
    }
`;
document.head.appendChild(style);
