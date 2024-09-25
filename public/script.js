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
                    videoItem.classList.add('video-item', 'advanced-video-card');
                    videoItem.setAttribute('data-video-url', video.url);
                    videoItem.setAttribute('data-progress', video.progress || 0); // Progress percentage
                    videoItem.innerHTML = `
                        <div class="progress-circle" data-progress="${video.progress || 0}">
                            <svg>
                                <circle cx="50" cy="50" r="45" stroke="#00e5ff" stroke-width="5" fill="none"/>
                                <circle cx="50" cy="50" r="45" stroke="#ffffff" stroke-width="5" fill="none" stroke-dasharray="283" stroke-dashoffset="283"/>
                            </svg>
                        </div>
                        <img src="${video.thumbnail || '/images/video-thumbnail1.jpg'}" alt="${video.title} Thumbnail" class="recent-video-thumbnail" onerror="this.src='/images/default-video-thumbnail.jpg'">
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
            const progress = parseFloat(circle.getAttribute('data-progress')) || 0;
            const offset = 283 - (283 * progress) / 100;
            const progressCircle = circle.querySelectorAll('circle')[1];
            progressCircle.style.strokeDashoffset = offset;
        });
    }

    // Initialize Vanilla Tilt for 3D Tilt Effect
    if (typeof VanillaTilt !== 'undefined') {
        VanillaTilt.init(document.querySelectorAll("[data-tilt]"), {
            max: 15,
            speed: 400,
            glare: true,
            "max-glare": 0.2,
        });
    } else {
        console.warn("VanillaTilt is not loaded.");
    }

    // Initialize Canvas-Based Molecular Structure Animation
    const canvas = document.getElementById('molecularCanvas');
    if (canvas) {
        const ctx = canvas.getContext('2d');

        let width, height;
        function resizeCanvas() {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
        }
        window.addEventListener('resize', resizeCanvas);
        resizeCanvas();

        // Molecular Node Structure
        const nodes = [];
        const nodeCount = 100; // Number of nodes

        // Initialize Nodes
        for (let i = 0; i < nodeCount; i++) {
            nodes.push({
                x: Math.random() * width,
                y: Math.random() * height,
                radius: Math.random() * 2 + 1,
                color: '#00e5ff',
                speed: Math.random() * 0.5 - 0.25, // -0.25 to 0.25
                direction: Math.random() * 2 * Math.PI
            });
        }

        // Draw Nodes and Connections
        function drawMolecules() {
            ctx.clearRect(0, 0, width, height);

            // Move Nodes
            nodes.forEach(node => {
                node.x += Math.cos(node.direction) * node.speed;
                node.y += Math.sin(node.direction) * node.speed;

                // Boundary Conditions
                if (node.x < 0 || node.x > width) {
                    node.direction = Math.PI - node.direction;
                }
                if (node.y < 0 || node.y > height) {
                    node.direction = -node.direction;
                }
            });

            // Draw Connections
            for (let i = 0; i < nodeCount; i++) {
                for (let j = i + 1; j < nodeCount; j++) {
                    const dx = nodes[i].x - nodes[j].x;
                    const dy = nodes[i].y - nodes[j].y;
                    const distance = Math.sqrt(dx * dx + dy * dy);
                    if (distance < 150) { // Connection distance threshold
                        ctx.strokeStyle = `rgba(0, 229, 255, ${1 - distance / 150})`; // Fading lines
                        ctx.lineWidth = 1;
                        ctx.beginPath();
                        ctx.moveTo(nodes[i].x, nodes[i].y);
                        ctx.lineTo(nodes[j].x, nodes[j].y);
                        ctx.stroke();
                    }
                }
            }

            // Draw Nodes
            nodes.forEach(node => {
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.radius, 0, 2 * Math.PI);
                ctx.fillStyle = node.color;
                ctx.fill();
            });

            requestAnimationFrame(drawMolecules);
        }

        drawMolecules();
    } else {
        console.error("Canvas element with id 'molecularCanvas' not found.");
    }

    // Dynamic Prompt Functionality (Existing)
    const fancyTitleElementForBlossom = document.querySelector('.site-title');
    if (fancyTitleElementForBlossom) {
        fancyTitleElementForBlossom.addEventListener('mouseover', function () {
            for (let i = 0; i < 50; i++) {
                createBlossom();
            }
        });
    }

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
