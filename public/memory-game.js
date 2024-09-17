document.addEventListener('DOMContentLoaded', () => {
    const cardArray = [
        { name: 'image1', img: '/images/image1.png' },
        { name: 'image1', img: '/images/image1.png' },
        { name: 'image2', img: '/images/image2.png' },
        { name: 'image2', img: '/images/image2.png' },
        { name: 'image3', img: '/images/image3.png' },
        { name: 'image3', img: '/images/image3.png' },
        { name: 'image4', img: '/images/image4.png' },
        { name: 'image4', img: '/images/image4.png' }
    ];


    cardArray.sort(() => 0.5 - Math.random());

    const gameBoard = document.getElementById('game-board');
    const gameStatus = document.getElementById('game-status');
    let chosenCards = [];
    let chosenCardsIds = [];
    let matchedCards = [];

    function createBoard() {
        for (let i = 0; i < cardArray.length; i++) {
            const card = document.createElement('div');
            card.setAttribute('class', 'card hidden');
            card.setAttribute('data-id', i);
            const cardImage = document.createElement('img');
            cardImage.setAttribute('src', cardArray[i].img);
            cardImage.setAttribute('alt', cardArray[i].name);
            card.appendChild(cardImage);
            card.addEventListener('click', flipCard);
            gameBoard.appendChild(card);
        }
    }

    function flipCard() {
        let cardId = this.getAttribute('data-id');
        if (chosenCardsIds.includes(cardId) || matchedCards.includes(cardId)) {
            return;
        }

        chosenCards.push(cardArray[cardId].name);
        chosenCardsIds.push(cardId);
        this.classList.add('flipped');

        if (chosenCards.length === 2) {
            setTimeout(checkForMatch, 500);
        }
    }

    function checkForMatch() {
        const cards = document.querySelectorAll('.card');
        const optionOneId = chosenCardsIds[0];
        const optionTwoId = chosenCardsIds[1];

        if (chosenCards[0] === chosenCards[1]) {
            matchedCards.push(optionOneId, optionTwoId);
            if (matchedCards.length === cardArray.length) {
                gameStatus.textContent = 'Congratulations! You matched all the cards.';
                setTimeout(() => {
                    
                    document.getElementById('game-modal').style.display = 'none';
                    document.getElementById('main-content').style.display = 'block';
                }, 2000);
            }
        } else {
            setTimeout(() => {
                cards[optionOneId].classList.remove('flipped');
                cards[optionTwoId].classList.remove('flipped');
            }, 500);
        }

        chosenCards = [];
        chosenCardsIds = [];
    }

    createBoard();
});
