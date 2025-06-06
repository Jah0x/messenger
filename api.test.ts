import { expect } from "expect";
import { authenticateWithLdap } from "./api";

async function testAuthenticateWithLdap() {
  // Тест успешной авторизации
  const validResult = await authenticateWithLdap({
    username: "admin",
    password: "password"
  });

  expect(validResult.success).toBe(true);
  expect(validResult.user).toBeDefined();
  expect(validResult.user?.username).toBe("admin");

  // Тест неуспешной авторизации
  const invalidResult = await authenticateWithLdap({
    username: "invalid",
    password: "wrong"
  });

  expect(invalidResult.success).toBe(false);
  expect(invalidResult.error).toBeDefined();
}

type TestResult = {
  passedTests: string[];
  failedTests: { name: string; error: string }[];
};

export async function _runApiTests() {
  const result: TestResult = { passedTests: [], failedTests: [] };

  const testFunctions = [testAuthenticateWithLdap];

  const finalResult = await testFunctions.reduce(
    async (promisedAcc, testFunction) => {
      const acc = await promisedAcc;
      try {
        await testFunction();
        return {
          ...acc,
          passedTests: [...acc.passedTests, testFunction.name],
        };
      } catch (error) {
        return {
          ...acc,
          failedTests: [
            ...acc.failedTests,
            {
              name: testFunction.name,
              error: error instanceof Error ? error.message : "Unknown error",
            },
          ],
        };
      }
    },
    Promise.resolve(result),
  );

  return finalResult;
}