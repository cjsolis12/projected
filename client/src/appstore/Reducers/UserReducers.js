import { createSlice } from '@reduxjs/toolkit'

const initialState = {
}

export const userSlice = createSlice({
  name: 'UserState',
  initialState,
  reducers: {
    login: (state,action) => {
        state.isLoggedIn = action.payload.value
    },
    logout: (state,action) => {
        state.isLoggedIn = action.payload.value
        state.userData = null;
    },
    setUserData:(state,action)=>{
        state.userData = action.payload
    },
    setLocation:(state, action)=>{
        console.log(action);
        state.userLocation = action.payload
    }
  },
})

// Action creators are generated for each case reducer function
export const { login, logout, setUserData,setLocation } = userSlice.actions;
export const currentUser = (state)=> state.userState.userData;
export const isLoggedIn = (state) => state.userState.isLoggedIn;
export const userLocation = (state) => state.userState.userLocation;
export default userSlice.reducer