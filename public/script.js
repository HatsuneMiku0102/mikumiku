document.addEventListener('DOMContentLoaded', function () {
    // Dynamic Typing Effect for Fancy Title
    const fancyTitleElement = document.getElementById('dynamicTitle');
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

    // Fetch Videos Data
    fetch('/videos.json')
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to fetch videos');
            }
            return response.json();
        })
        .then(data => {
            const videoContainer = document.getElementById('recent-videos-container');
            if (data && data.length) {
                data.forEach(video => {
                    const videoItem = document.createElement('div');
                    videoItem.classList.add('video-item');
                    videoItem.setAttribute('data-video-url', video.url);
                    videoItem.classList.add('advanced-video-card'); // Ensure video cards have the correct class
                    videoItem.setAttribute('data-progress', video.progress || 0); // Progress percentage
                    videoItem.innerHTML = `
                        <div class="progress-circle" data-progress="${video.progress || 0}">
                            <svg>
                                <circle cx="50" cy="50" r="45" stroke="#00e5ff" stroke-width="5" fill="none"/>
                                <circle cx="50" cy="50" r="45" stroke="#ffffff" stroke-width="5" fill="none" stroke-dasharray="283" stroke-dashoffset="283"/>
                            </svg>
                        </div>
                        <img src="https://img.youtube.com/vi/${video.url.split('/').pop()}/0.jpg" alt="${video.title} Thumbnail" class="recent-video-thumbnail">
                        <p class="recent-video-title">${video.title}</p>
                        <div class="video-info-overlay">
                            <button class="play-button">
                                <svg class="play-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="24" height="24">
                                    <circle cx="32" cy="32" r="30" stroke="#00e5ff" stroke-width="4" fill="none"/>
                                    <polygon points="26,20 26,44 46,32" fill="#00e5ff"/>
                                </svg>
                                Play
                            </button>
                        </div>
                    `;
                    videoContainer.appendChild(videoItem);
                });
                initializeVideoLoading();
                initializeProgressCircles();
            } else {
                videoContainer.innerHTML = '<p>No videos available</p>';
            }
        })
        .catch(error => {
            console.error('Error fetching video data:', error);
            document.getElementById('recent-videos-container').innerHTML = '<p>Error loading videos.</p>';
        });

    // Initialize Video Loading with IntersectionObserver and Click Events
    function initializeVideoLoading() {
        const loadVideo = (container) => {
            const videoUrl = container.getAttribute("data-video-url");
            if (!videoUrl) return;
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

        document.querySelectorAll(".recent-video-thumbnail").forEach(thumbnail => {
            thumbnail.addEventListener("click", function () {
                const container = thumbnail.parentElement;
                loadVideo(container);
            });
        });

        document.querySelectorAll(".play-button").forEach(button => {
            button.addEventListener("click", function () {
                const container = button.parentElement;
                loadVideo(container);
            });
        });
    }

    // Initialize Circular Progress Indicators
    function initializeProgressCircles() {
        document.querySelectorAll('.progress-circle').forEach(circle => {
            const progress = circle.getAttribute('data-progress') || 0;
            const offset = 283 - (283 * progress) / 100;
            const progressCircle = circle.querySelectorAll('circle')[1];
            progressCircle.style.strokeDashoffset = offset;
        });
    }

    // Initialize Vanilla Tilt for 3D Tilt Effect
    VanillaTilt.init(document.querySelectorAll("[data-tilt]"), {
        max: 15,
        speed: 400,
        glare: true,
        "max-glare": 0.2,
    });

    // Initialize Particles.js for Particle Background (Optional)
    // Uncomment the following lines if you want to use Particles.js
    /*
    particlesJS.load('particles-js', '/path-to-your-particles.json', function() {
        console.log('Particles.js loaded - callback');
    });
    */

    // Initialize Canvas-Based Wave Animation
    const canvas = document.getElementById('waveCanvas');
    const ctx = canvas.getContext('2d');

    let width, height;
    function resizeCanvas() {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    }
    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();

    const waves = [];
    const waveCount = 3;
    for (let i = 0; i < waveCount; i++) {
        waves.push({
            amplitude: 20 + i * 10,
            wavelength: 100 + i * 50,
            speed: 0.02 + i * 0.01,
            phase: 0,
            color: `rgba(0, 229, 255, ${0.3 + i * 0.2})` // Miku's teal shades
        });
    }

    function drawWave(wave) {
        ctx.beginPath();
        ctx.moveTo(0, height / 2);
        for (let x = 0; x < width; x++) {
            const y = height / 2 + wave.amplitude * Math.sin((x / wave.wavelength) * 2 * Math.PI + wave.phase);
            ctx.lineTo(x, y);
        }
        ctx.strokeStyle = wave.color;
        ctx.lineWidth = 2;
        ctx.stroke();
    }

    function animate() {
        ctx.clearRect(0, 0, width, height);
        waves.forEach(wave => {
            drawWave(wave);
            wave.phase += wave.speed;
        });
        requestAnimationFrame(animate);
    }
    animate();

    // Dynamic Prompt Functionality (Existing)
    document.querySelector('.fancy-title')?.addEventListener('mouseover', function () {
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
