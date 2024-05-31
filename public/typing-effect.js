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
