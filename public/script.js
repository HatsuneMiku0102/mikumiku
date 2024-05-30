
console.log("Welcome to MikuMiku <3");

document.addEventListener('DOMContentLoaded', function() {
    const textElement = document.getElementById('typing-text');
    const text = 'MikuMiku';
    const typingSpeed = 200;

    let index = 0;

    function typeCharacter() {
        if (index < text.length) {
            textElement.innerHTML += text[index];
            index++;
            setTimeout(typeCharacter, typingSpeed);
        }
    }

    typeCharacter();
});

document.addEventListener('DOMContentLoaded', function() {
    const textElement = document.getElementById('fancy-title');
    const text = 'Vocaloid Tracks <3';
    const typingSpeed = 300;

    const words = text.split(' ');
    let wordIndex = 0;

    function typeWord() {
        if (wordIndex < words.length) {
            textElement.innerHTML += (wordIndex > 0 ? ' ' : '') + words[wordIndex];
            wordIndex++;
            setTimeout(typeWord, typingSpeed);
        }
    }

    typeWord();
});

document.querySelector('.fancy-title').addEventListener('mouseover', function() {
    for (let i = 0; i < 50; i++) {
        createBlossom();
    }
});

function createBlossom() {
    const blossom = document.createElement('div');
    blossom.classList.add('blossom');
    blossom.style.left = `${Math.random() * 100}%`;
    blossom.style.animationDuration = `${Math.random() * 5 + 3}s`;
    document.body.appendChild(blossom);

    setTimeout(() => {
        blossom.remove();
    }, 8000);
}

document.addEventListener("DOMContentLoaded", function() {
    const videoContainers = document.querySelectorAll(".video-item");

    const loadVideo = (container) => {
        const videoId = container.getAttribute("data-video-id");
        const iframe = document.createElement("iframe");
        iframe.width = "560";
        iframe.height = "315";
        iframe.src = `https://www.youtube.com/embed/${videoId}`;
        iframe.frameBorder = "0";
        iframe.allow = "accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture";
        iframe.allowFullscreen = true;
        container.innerHTML = "";
        container.appendChild(iframe);
    };

    const onIntersection = (entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                loadVideo(entry.target);
                observer.unobserve(entry.target);
            }
        });
    };

    const observer = new IntersectionObserver(onIntersection, {
        root: null,
        rootMargin: "0px",
        threshold: 0.1
    });

    videoContainers.forEach(container => {
        observer.observe(container);
    });

    document.querySelectorAll(".video-thumbnail").forEach(thumbnail => {
        thumbnail.addEventListener("click", function() {
            const container = thumbnail.parentElement;
            loadVideo(container);
        });
    });

    document.querySelectorAll(".play-button").forEach(button => {
        button.addEventListener("click", function() {
            const container = button.parentElement;
            loadVideo(container);
        });
    });
});



