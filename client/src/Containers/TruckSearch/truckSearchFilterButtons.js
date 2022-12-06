import React, { Fragment } from "react";
import './style.css';


const TruckSearchFilterButtons = () => {

    const handleClick=(e)=>{
        console.log(e.target.value);
    }
    return (
        <Fragment>
            <button className='filterButton' >Search By Title</button>
            <button className='filterButton' >Search By Flavor</button>
            <button className='filterButton' >Search By How long on app</button>
            <button className='filterButton' >Search By something else </button>
        </Fragment>
    )
}

export default TruckSearchFilterButtons;