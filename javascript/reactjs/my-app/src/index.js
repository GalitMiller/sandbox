import React from 'react'
import ReactDOM from 'react-dom'
import Button from 'react-bootstrap/Button'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'

import { library } from '@fortawesome/fontawesome-svg-core'
import { fal } from '@fortawesome/pro-light-svg-icons'

import 'bootstrap/dist/css/bootstrap.min.css'
import './index.css'

library.add(fal)

const Sort = ({children, by}) => {
  if (!by) return children
  return children.sort(by)
}

function Square(props) {
  return (
    <Button
      variant={props.winner ? "outline-success" : "outline-info"}
      className="square"
      onClick={props.onClick}>
      {props.value || ' '}
    </Button>
  );
}

class Board extends React.Component {
  renderSquare(i) {
    const isWinner = this.props.results && this.props.results.winningSquares.find(s => s === i) !== undefined
    return (
      <Square key={i}
        value={this.props.squares[i]}
        winner={isWinner}
        onClick={() => this.props.onClick(i)}
      />
    )
  }

  render() {
    const rows = [0, 3, 6].map((row) => (
      <div className="board-row" key={row}>
        {[0, 1, 2].map(col => this.renderSquare(row + col))}
      </div>
    ));

    return <div className="board"> {rows} </div>
  }
}

function HistoricalSquare(props) {
  return (
    <div
      variant="outline-info"
      className="static-square">
      {props.value || ' '}
    </div>
  );
}

class HistoricalBoard extends React.Component {
  renderSquare(i) {
    return (
      <HistoricalSquare key={i}
        value={this.props.squares[i]}
      />
    );
  }

  render() {
    const rows = [0, 3, 6].map((row) => (
      <div className="static-board-row" key={row}>
        {[0, 1, 2].map(col => this.renderSquare(row + col))}
      </div>
    ));

    return <div className="static-board"> {rows} </div>
  }
}

class Game extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      history: [{ squares: Array(9).fill(null), stepNumber: 0 }],
      stepNumber: 0,
      xIsNext: true,
      sortOrder: true,
    };
  }

  handleClick(i) {
    const history = this.state.history.slice(0, this.state.history.length);
    const current = history[history.length - 1];
    const squares = current.squares.slice();
    if (calculateWinner(squares) || squares[i]) {
      return;
    }
    squares[i] = this.state.xIsNext ? "X" : "O";
    this.setState({
      history: history.concat([{ squares: squares, stepNumber: history.length }]),
      stepNumber: history.length,
      xIsNext: !this.state.xIsNext
    });
  }

  jumpTo(step) {
    this && this.setState({
      history: this.state.history.slice(0, step + 1),
      stepNumber: step,
      xIsNext: (step % 2) === 0,
    });
  }

  handleSort() {
    this && this.setState({
      sortOrder: !this.state.sortOrder,
    })
  }

  render() {
    const history = this.state.history;
    const current = history[this.state.stepNumber];
    const results = calculateWinner(current.squares);

    const moves = history.map((step, move) => (
      <li key={move} stepnumber={step.stepNumber}>
        <Button
          className="history-button"
          variant="outline-dark"
          onClick={()=>this.jumpTo(move)}>
          <HistoricalBoard squares={step.squares}/>
        </Button>
      </li>
    ))

    let historySorter = (a, b) => {
      return this.state.sortOrder
        ? a.props['stepnumber'] - b.props['stepnumber']
        : b.props['stepnumber'] - a.props['stepnumber']
    }

    return (
      <div className="game">
        <div>
          <Board
            squares={current.squares}
            results={results}
            onClick={i => this.handleClick(i)}
          />
        </div>
        <div className="game-info">
          <div>{results
            ? "Winner: " + results.winner + ' ' + results.winningSquares
            : "Next player: " + (this.state.xIsNext ? "X" : "O")}
          </div>
          <Button
            variant="outline-info"
            onClick={()=> this.handleSort()}>
            <FontAwesomeIcon icon={this.state.sortOrder ? ["fal", "sort-numeric-up"] : ["fal", "sort-numeric-down"]} />
          </Button>
          <ol><Sort by={historySorter}>{moves}</Sort></ol>
        </div>
      </div>
    );
  }
}

// ========================================

ReactDOM.render(<Game />, document.getElementById("root"));

function calculateWinner(squares) {
  const lines = [
    [0, 1, 2],
    [3, 4, 5],
    [6, 7, 8],
    [0, 3, 6],
    [1, 4, 7],
    [2, 5, 8],
    [0, 4, 8],
    [2, 4, 6]
  ];
  for (let i = 0; i < lines.length; i++) {
    const [a, b, c] = lines[i];
    if (squares[a] && squares[a] === squares[b] && squares[a] === squares[c]) {
      return {winner: squares[a], winningSquares: lines[i]};
    }
  }
  return null;
}
