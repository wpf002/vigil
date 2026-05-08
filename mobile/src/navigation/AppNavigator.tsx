import React from 'react';
import {ActivityIndicator, StyleSheet, Text, TouchableOpacity, View} from 'react-native';
import {NavigationContainer, DarkTheme} from '@react-navigation/native';
import {createStackNavigator} from '@react-navigation/stack';
import {useAuth} from '../context/AuthContext';
import {LoginScreen} from '../screens/LoginScreen';
import {EscalationQueueScreen} from '../screens/EscalationQueueScreen';
import {EscalationDetailScreen} from '../screens/EscalationDetailScreen';
import {AttackDetailScreen} from '../screens/AttackDetailScreen';
import {SettingsScreen} from '../screens/SettingsScreen';

export type RootStackParamList = {
  Login: undefined;
  EscalationQueue: undefined;
  EscalationDetail: {queue_id: string; attack_id: string};
  AttackDetail: {attack_id: string};
  Settings: undefined;
};

const Stack = createStackNavigator<RootStackParamList>();

const theme = {
  ...DarkTheme,
  colors: {
    ...DarkTheme.colors,
    background: '#0a0a0a',
    card: '#1a1a1a',
    text: '#ffffff',
    border: '#27272a',
    primary: '#dc2626',
  },
};

export function AppNavigator() {
  const {authenticated, loading} = useAuth();

  if (loading) {
    return (
      <View style={styles.splash}>
        <ActivityIndicator color="#dc2626" />
      </View>
    );
  }

  return (
    <NavigationContainer theme={theme}>
      <Stack.Navigator
        screenOptions={{
          headerStyle: {backgroundColor: '#0a0a0a', borderBottomColor: '#27272a', borderBottomWidth: 1},
          headerTitleStyle: {fontFamily: 'Menlo', fontSize: 14, color: '#fff', letterSpacing: 2},
          headerTintColor: '#fff',
        }}>
        {!authenticated ? (
          <Stack.Screen
            name="Login"
            component={LoginScreen}
            options={{headerShown: false}}
          />
        ) : (
          <>
            <Stack.Screen
              name="EscalationQueue"
              component={EscalationQueueScreen}
              options={({navigation}) => ({
                title: 'VIGIL · ESCALATIONS',
                headerRight: () => (
                  <TouchableOpacity
                    onPress={() => navigation.navigate('Settings')}
                    style={{paddingHorizontal: 12}}>
                    <Text style={styles.headerLink}>SETTINGS</Text>
                  </TouchableOpacity>
                ),
              })}
            />
            <Stack.Screen
              name="EscalationDetail"
              component={EscalationDetailScreen}
              options={{title: 'ESCALATION'}}
            />
            <Stack.Screen
              name="AttackDetail"
              component={AttackDetailScreen}
              options={{title: 'ATTACK'}}
            />
            <Stack.Screen
              name="Settings"
              component={SettingsScreen}
              options={{title: 'SETTINGS'}}
            />
          </>
        )}
      </Stack.Navigator>
    </NavigationContainer>
  );
}

const styles = StyleSheet.create({
  splash: {flex: 1, alignItems: 'center', justifyContent: 'center', backgroundColor: '#0a0a0a'},
  headerLink: {fontFamily: 'Menlo', fontSize: 11, color: '#9ca3af', letterSpacing: 1},
});
