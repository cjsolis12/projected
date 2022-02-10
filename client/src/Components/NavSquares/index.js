import {
    Col,
    Row,
    Container,
    Form,
    Button,
    Nav
} from 'react-bootstrap'
import './style.css';
const routes = [

    {
        name: 'Check Weather',
        link: "checkweather"
    },
    {
        name: 'Weather Trends',
        link: "weathertrends"
    },
    {
        name: 'Trash Trends',
        link: "trashtrends"
    },
    {
        name: 'Status of the Ozone',
        link: "ozonestatus"
    }
];

const NavSquares = () => {
    return (
        <Container 
            style = {{marginTop: '10%'}}
        >
            <Row>
                {routes.map((route) => (

                    <Col xs={12} md={4} lg={3} xl={3}>
                        <div className='navSquare'>
                            <Nav.Link href={route.link}>

                                <div className= "squareText">
                                    {route.name}
                                </div>
                            </Nav.Link>
                        </div>
                    </Col>

                ))}
            </Row>
        </Container>
    )
}

export default NavSquares;