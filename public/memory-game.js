document.addEventListener('DOMContentLoaded', () => {
    const cardArray = [
        { name: 'A', value: 'A' },
        { name: 'A', value: 'A' },
        { name: 'B', value: 'B' },
        { name: 'B', value: 'B' },
        { name: 'C', value: 'C' },
        { name: 'C', value: 'C' },
        { name: 'D', value: 'D' },
        { name: 'D', value: 'D' }
    ];

    // Shuffle the cards
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
            card.addEventListener('click', flipCard);
            gameBoard.appendChild(card);
        }
    }

    function flipCard() {
        let cardId = this.getAttribute('data-id');
        if (chosenCardsIds.includes(cardId) || matchedCards.includes(cardId)) {
            return;
        }

        chosenCards.push(cardArray[cardId].value);
        chosenCardsIds.push(cardId);
        this.classList.remove('hidden');
        this.textContent = cardArray[cardId].value;

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
                    // Hide the game modal and show the main content
                    document.getElementById('game-modal').style.display = 'none';
                    document.getElementById('main-content').style.display = 'block';
                }, 2000);
            }
        } else {
            cards[optionOneId].classList.add('hidden');
            cards[optionOneId].textContent = '';
            cards[optionTwoId].classList.add('hidden');
            cards[optionTwoId].textContent = '';
        }

        chosenCards = [];
        chosenCardsIds = [];
    }

    createBoard();
});
