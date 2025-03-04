/*
const userInputData = {
  inputData: '',
  inputType: 'Decimal', 
};

export default userInputData;

*/
class UserInputData {
  constructor(inputData = '', inputType = 'Decimal') {
    this.inputData = inputData;
    this.inputType = inputType;
  }
}

export default UserInputData;