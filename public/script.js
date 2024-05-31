document.addEventListener('DOMContentLoaded', function() {

    const fancyTitleElement = document.getElementById('fancy-title');
    const fancyText = 'Vocaloid Tracks <3';
    const fancyTypingSpeed = 300;

    function typeFancyWord(element, text, speed) {
        element.innerHTML = '';
        const words = text.split(' ');
        let wordIndex = 0;

        function type() {
            if (wordIndex < words.length) {
                element.innerHTML += (wordIndex > 0 ? ' ' : '') + words[wordIndex];
                wordIndex++;
                setTimeout(type, speed);
            }
        }
        type();
    }

    typeFancyWord(fancyTitleElement, fancyText, fancyTypingSpeed);


    fetch('/videos.json')
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to fetch videos');
            }
            return response.json();
        })
        .then(data => {
            const videoContainer = document.getElementById('video-container');
            if (data && data.length) {
                data.forEach(video => {
                    const videoItem = document.createElement('div');
                    videoItem.classList.add('video-item');
                    videoItem.setAttribute('data-video-url', video.url);
                    videoItem.innerHTML = `
                        <img src="https://img.youtube.com/vi/${video.url.split('/').pop()}/0.jpg" alt="${video.title} Thumbnail" class="video-thumbnail">
                        <button class="play-button">Play</button>
                        <h3>${video.title}</h3>
                        <p>${video.description}</p>
                    `;
                    videoContainer.appendChild(videoItem);
                });
            } else {
                videoContainer.innerHTML = '<p>No videos available</p>';
            }
        })
        .catch(error => {
            console.error('Error fetching video data:', error);
            document.getElementById('video-container').innerHTML = '<p>Error loading videos.</p>';
        });


    const loadVideo = (container) => {
        const videoUrl = container.getAttribute("data-video-url");
        const iframe = document.createElement("iframe");
        iframe.width = "560";
        iframe.height = "315";
        iframe.src = videoUrl;
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

    document.querySelectorAll(".video-item").forEach(container => {
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

    document.querySelector('.fancy-title').addEventListener('mouseover', function () {
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
});
